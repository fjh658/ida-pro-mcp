# -*- coding: utf-8 -*-
"""
Computed-Branch Deobfuscator -- Hex-Rays Microcode Plugin
=================================================================

IDA Plugin that resolves computed indirect jumps (BR Xn on ARM64,
JMP reg on x86_64) at the Hex-Rays microcode level.

Usage (three modes):

  1) Script File (one-shot full repair):
       File -> Script File -> select this script.
       Auto-installs optimizer and runs fix_all on every function
       (with progress dialog, cancellable).

  2) Plugin (incremental + menus):
       Copy this file to IDA's `plugins/` directory (or use --install).
       - F5 / Tab on any function triggers deobfuscation automatically.
       - Edit -> CB Deobf -> Fix All Functions   (batch scan)
       - Edit -> CB Deobf -> Fix Current Function
       - Edit -> CB Deobf -> Toggle Deobfuscator
       - Right-click in disassembly or pseudocode -> CB Deobf/ submenu
       - Edit -> Plugins -> CB Deobfuscator   (toggle on/off)
       - Hotkey: Ctrl-Shift-A  (configurable below via PLUGIN_HOTKEY)

  3) CLI (install/uninstall from terminal):
       python3 computed_branch_deobf.py --install          # copy to plugins dir
       python3 computed_branch_deobf.py --install --force   # overwrite existing
       python3 computed_branch_deobf.py --uninstall         # remove from plugins dir
       python3 computed_branch_deobf.py --version           # show version
"""

# ---------------------------------------------------------------------------
# CLI installer (standalone Python, outside IDA)
# ---------------------------------------------------------------------------

def _cli_main(script_name, display_name, version):
    """Install/uninstall this plugin to IDA's plugins directory."""
    import argparse, os, platform, shutil

    def _ida_plugins_dir():
        if platform.system() == "Windows":
            appdata = os.environ.get("APPDATA")
            if appdata:
                d = os.path.join(appdata, "Hex-Rays", "IDA Pro", "plugins")
                if os.path.isdir(os.path.dirname(d)):
                    return d
        return os.path.join(os.path.expanduser("~"), ".idapro", "plugins")

    parser = argparse.ArgumentParser(
        prog=script_name,
        description=f"{display_name} — Hex-Rays microcode plugin (v{version})",
        epilog="Inside IDA: File → Script File, or copy to plugins/ dir.")
    parser.add_argument("--version", "-V", action="version",
                        version=f"{script_name} {version}")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--install", action="store_true",
                       help="Copy this script to the IDA plugins directory")
    group.add_argument("--uninstall", action="store_true",
                       help="Remove this script from the IDA plugins directory")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite even if already installed")
    args = parser.parse_args()

    if not args.install and not args.uninstall:
        parser.print_help()
        raise SystemExit(0)

    src = os.path.realpath(__file__)
    plugins_dir = _ida_plugins_dir()
    dst = os.path.join(plugins_dir, os.path.basename(src))

    if args.install:
        if os.path.exists(dst) and not args.force:
            print(f"Already installed: {dst}\nUse --force to overwrite.")
            raise SystemExit(0)
        os.makedirs(plugins_dir, exist_ok=True)
        if os.path.exists(dst):
            os.remove(dst)
        shutil.copy2(src, dst)
        print(f"Installed: {src}\n      -> {dst}")
    else:
        if os.path.exists(dst):
            os.remove(dst)
            print(f"Uninstalled: {dst}")
        else:
            print(f"Not found: {dst}")


# ---------------------------------------------------------------------------
# Entry point — detect IDA vs standalone Python
# ---------------------------------------------------------------------------

_SCRIPT_MODE = False

if __name__ == "__main__":
    import importlib.util, sys
    if importlib.util.find_spec("ida_hexrays") is not None:
        _SCRIPT_MODE = True
    else:
        _cli_main("computed_branch_deobf", "CB Deobfuscator", "0.0.1")
        sys.exit(0)

import ida_hexrays
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_ua
import ida_nalt
import ida_idp
import ida_funcs
import ida_auto
import ida_name
import struct
import traceback

try:
    import ida_allins
except ImportError:
    ida_allins = None

try:
    import ida_ida
except ImportError:
    ida_ida = None

try:
    import idc as _idc
except ImportError:
    _idc = None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DEBUG = True
VERBOSE = False  # set True for per-block diagnostic dumps

import time as _time
import threading as _threading

def _ts():
    """Current timestamp with local timezone, e.g. '2026-02-28 23:20:31.123 +0800'."""
    t = _time.time()
    lt = _time.localtime(t)
    return _time.strftime("%Y-%m-%d %H:%M:%S", lt) + ".%03d " % (t % 1 * 1000) + _time.strftime("%z", lt)

def _log(msg):
    if DEBUG:
        print("[%s][cb_deobf_mc] %s" % (_ts(), msg))

def _vlog(msg):
    if VERBOSE:
        print("[%s][cb_deobf_mc] %s" % (_ts(), msg))


def _get_disasm(ea):
    """Get disassembly text at *ea* (before any patching)."""
    try:
        return _idc.GetDisasm(ea) if _idc else "???"
    except Exception:
        return "???"


# ---------------------------------------------------------------------------
# Standalone decompile-with-timeout  (no plugin dependencies — copy-paste OK)
# ---------------------------------------------------------------------------

from decompile_timeout import decompile_cfunc as decompile_with_timeout


def _has_large_jump_table(f_start, f_end):
    """Return True if the function contains a large indirect jump table.

    Functions with >100-entry jump tables cause the decompiler's CLP
    solver to run for tens of seconds.  Skipping them avoids the
    timeout penalty (~20s per function).

    Detected patterns:
      x86_64: ``jmp qword [reg + idx*8]`` with switch_info > 100 cases
      ARM64:  ``BR Xn`` (register-indirect jump)
    """
    f_size = f_end - f_start
    if f_size > 0x40:
        return False  # too large to be a stub

    # Decode instructions in the function
    insns = []
    ea = f_start
    while ea < f_end and len(insns) < 8:
        insn = ida_ua.insn_t()
        n = ida_ua.decode_insn(insn, ea)
        if n == 0:
            break
        insns.append(insn)
        ea += n

    if len(insns) < 2 or ida_allins is None:
        return False

    if _is_arm64():
        # ARM64: look for BR Xn at the end
        last = insns[-1]
        if last.itype == ida_allins.ARM_br:
            return True
    else:
        # x86_64: look for JMP [reg + reg*8] or JMP [table + reg*8]
        # as the last (or second-to-last) instruction
        for insn in insns[-2:]:
            if insn.itype in (ida_allins.NN_jmp, ida_allins.NN_jmpni):
                op = insn.ops[0]
                # Indirect jump through memory with SIB scale=8
                if op.type in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ):
                    # Check for switch info (IDA's own detection)
                    si = ida_nalt.switch_info_t()
                    if ida_nalt.get_switch_info(si, insn.ea):
                        if si.get_jtable_size() > 100:
                            return True
    return False


# ---------------------------------------------------------------------------
# Architecture detection & arch-aware helpers
# ---------------------------------------------------------------------------

_ARCH = "x86"  # will be set by cb_deobf_install()


def _detect_arch():
    """Return ``'x86'`` or ``'arm64'`` based on IDA processor info."""
    pname = ida_ida.inf_get_procname().lower() if ida_ida else "x86"
    if "arm" in pname or "aarch" in pname:
        return "arm64"
    return "x86"


def _is_arm64():
    return _ARCH == "arm64"


def _insn_align():
    """Minimum instruction alignment (4 for ARM64, 1 for x86)."""
    return 4 if _is_arm64() else 1


def _nop_at(ea):
    """Patch ONE NOP instruction at *ea*. Returns byte count written."""
    if _is_arm64():
        # ARM64 NOP: D503201F  ->  bytes 1F 20 03 D5 (little-endian)
        for i, b in enumerate((0x1F, 0x20, 0x03, 0xD5)):
            ida_bytes.patch_byte(ea + i, b)
        return 4
    ida_bytes.patch_byte(ea, 0x90)
    return 1


def _nop_range(start, end):
    """Fill [start, end) with architecture-appropriate NOPs."""
    ea = start
    while ea < end:
        ea += _nop_at(ea)


def _patch_direct_branch(from_ea, to_ea, insn_len):
    """Patch a direct unconditional branch at *from_ea* -> *to_ea*.

    NOP-pads the remaining bytes of the original instruction (of size
    *insn_len*).  Returns True on success.
    """
    if _is_arm64():
        offset = to_ea - from_ea
        if offset % 4 != 0:
            _log("  patch-branch: ARM64 offset 0x%X not 4-aligned" % offset)
            return False
        imm26 = (offset >> 2) & 0x03FFFFFF
        enc = 0x14000000 | imm26
        for i in range(4):
            ida_bytes.patch_byte(from_ea + i, (enc >> (i * 8)) & 0xFF)
        # NOP remaining (ARM64 insn is always 4 bytes so usually 0 extra)
        ea = from_ea + 4
        while ea < from_ea + insn_len:
            ea += _nop_at(ea)
        return True

    # x86: try short JMP (EB rel8) first, then near JMP (E9 rel32)
    next_ea = from_ea + 2
    rel8 = to_ea - next_ea
    if -128 <= rel8 <= 127 and insn_len >= 2:
        ida_bytes.patch_byte(from_ea, 0xEB)
        ida_bytes.patch_byte(from_ea + 1, rel8 & 0xFF)
        for i in range(2, insn_len):
            ida_bytes.patch_byte(from_ea + i, 0x90)
        return True
    next_ea5 = from_ea + 5
    rel32 = to_ea - next_ea5
    if insn_len >= 5:
        ida_bytes.patch_byte(from_ea, 0xE9)
        for i in range(4):
            ida_bytes.patch_byte(from_ea + 1 + i, (rel32 >> (i * 8)) & 0xFF)
        for i in range(5, insn_len):
            ida_bytes.patch_byte(from_ea + i, 0x90)
        return True
    return False


def _decode_ret_at(ea):
    """If there is a RET instruction at *ea*, return its byte-length.

    Returns 0 if no RET at *ea*.  Uses ``ida_idp.is_ret_insn()`` so the
    check is architecture-independent (x86, ARM64, MIPS, etc.).
    """
    insn = ida_ua.insn_t()
    n = ida_ua.decode_insn(insn, ea)
    if n <= 0:
        return 0
    return n if ida_idp.is_ret_insn(insn) else 0


def _is_ret_at(ea):
    """Return True if there is a RET instruction at *ea*."""
    return _decode_ret_at(ea) > 0


def _ret_size_at(ea):
    """Return the byte-length of the RET instruction at *ea* (or 0)."""
    return _decode_ret_at(ea)


def _is_prologue_at(ea):
    """Return True if a function prologue starts at *ea*.

    Uses ``decode_insn`` to check instruction semantics rather than
    matching raw bytes, so it covers more prologue variants.  Falls
    back to byte-matching only when decode fails.
    """
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return False

    if _is_arm64():
        # STP X29, X30, [SP, #imm]!  -- most common ARM64 prologue.
        # Try ida_allins.ARM_stp first (stable in modern IDA 8+).
        try:
            if ida_allins and insn.itype == ida_allins.ARM_stp:
                # Verify operands: Rt=X29, Rt2=X30, Rn=SP
                # Check raw encoding for register fields since operand
                # access API varies across IDA versions.
                val = _read_u32_le(ea)
                rt  = val & 0x1F          # bits[4:0]   = Rt
                rn  = (val >> 5) & 0x1F   # bits[9:5]   = Rn
                rt2 = (val >> 10) & 0x1F  # bits[14:10]  = Rt2
                return rt == 29 and rt2 == 30 and rn == 31  # X29, X30, SP
        except (AttributeError, TypeError):
            pass
        # Fallback: raw encoding match for older IDA versions.
        val = _read_u32_le(ea)
        low = val & 0x7FFF   # Rt2=30, Rn=31, Rt=29
        if low == 0x7BFD:
            top = val & 0xFFC00000
            if top in (0xA9800000, 0xA9000000, 0xA8800000):
                return True

        # ARM64 prologue variant: SUB SP, SP, #imm  followed by STP.
        # Many obfuscated functions start with SUB SP before the STP
        # chain.  We verify the next instruction is STP to reduce false
        # positives (SUB SP can also appear mid-function as alloca).
        # SUB (immediate) with Rd=SP, Rn=SP:
        #   sf=1 op=1 S=0 -> 0xD1  (64-bit SUB)
        #   sf=0 op=1 S=0 -> 0x51  (32-bit SUB -- rare for SP)
        top_byte = (val >> 24) & 0xFF
        if top_byte in (0xD1, 0x51):
            rd = val & 0x1F
            rn = (val >> 5) & 0x1F
            if rd == 31 and rn == 31:  # SP, SP
                # Check next instruction is STP (callee-saved reg save)
                nxt = _read_u32_le(ea + 4)
                nxt_top = (nxt >> 22) & 0x3FF  # bits[31:22]
                # STP (pre-index/signed-offset/post-index) for X regs:
                # 0b10_101_0010 (signed offset) = 0x2A4
                # 0b10_101_0110 (pre-index)     = 0x2A6
                # 0b10_101_0001 (post-index)    = 0x2A1
                if nxt_top in (0x2A4, 0x2A6, 0x2A1):
                    return True
        return False

    # x86: push rbp; mov rbp, rsp  (classic prologue)
    # Verify PUSH operand is specifically RBP (reg 5) and MOV is RBP <- RSP
    # to avoid false positives on PUSH RAX/RBX/etc in mid-function code.
    try:
        if ida_allins and insn.itype == ida_allins.NN_push:
            # Operand must be RBP (o_reg=1, reg index 5 on x86)
            try:
                op0 = insn.ops[0]
                if op0.type != 1 or op0.reg != 5:  # not RBP
                    return False
            except (AttributeError, IndexError):
                # Can't verify operand -- fall through to byte check
                return False
            # Check next insn is mov rbp, rsp
            insn2 = ida_ua.insn_t()
            n2 = ida_ua.decode_insn(insn2, ea + insn.size)
            if n2 > 0 and insn2.itype == ida_allins.NN_mov:
                try:
                    d = insn2.ops[0]
                    s = insn2.ops[1]
                    if d.type == 1 and d.reg == 5 and s.type == 1 and s.reg == 4:
                        return True  # MOV RBP, RSP confirmed
                except (AttributeError, IndexError):
                    return True  # can't check MOV operands, trust pattern
                return False  # MOV but not RBP <- RSP
    except (AttributeError, TypeError):
        pass

    # Final fallback: exact byte match
    return (ida_bytes.get_byte(ea) == 0x55
            and ida_bytes.get_byte(ea + 1) == 0x48
            and ida_bytes.get_byte(ea + 2) == 0x89
            and ida_bytes.get_byte(ea + 3) == 0xE5)


def _read_u32_le(ea):
    """Read a little-endian 32-bit word from the IDB."""
    return ida_bytes.get_dword(ea)


def _scan_for_func_end(start_addr, limit=0x1000):
    """Scan forward from *start_addr* for a RET or next-function prologue.

    Returns the address just past the RET instruction, or the prologue
    address (for tail-call cases), or 0 if nothing found within *limit*
    bytes.
    """
    step = _insn_align()
    ea = start_addr
    ea_limit = start_addr + limit
    while ea < ea_limit:
        insn = ida_ua.insn_t()
        il = ida_ua.decode_insn(insn, ea)
        if il <= 0:
            ea += step
            continue
        ret_sz = _decode_ret_at(ea)
        if ret_sz > 0:
            return ea + ret_sz
        if ea > start_addr + 4 and _is_prologue_at(ea):
            _log("  scan-func-end: prologue at 0x%X ends func (tail call)" % ea)
            return ea
        ea += il
    return 0


def _nop_arm64_literal_loads(code_start, code_end, nop_start, nop_end):
    """ARM64-only: scan [code_start, code_end) for LDR/LDRSW literal-pool
    load instructions whose literal-pool target falls inside
    [nop_start, nop_end) (the NOP / junk zone).

    Patches each such instruction to NOP so that IDA no longer creates a
    data reference (DCD) at the literal-pool address, which would prevent
    code conversion.

    Returns a list of ``(insn_ea, literal_pool_ea, orig_disasm)`` for
    comment purposes.  MUST be called inside the optimizer callback where
    patch_byte is safe."""
    if not _is_arm64():
        return []

    patched = []
    ea = code_start
    # Align to 4-byte boundary
    if ea % 4:
        ea += 4 - (ea % 4)
    while ea < code_end:
        val = _read_u32_le(ea)
        # LDR (literal) family:
        #   bits[31:30]=opc, bit[29:27]=011, bit[26]=V, bit[25:24]=00
        #   LDR  Wt  : opc=00 V=0 -> top byte 0x18
        #   LDR  Xt  : opc=01 V=0 -> top byte 0x58
        #   LDRSW Xt : opc=10 V=0 -> top byte 0x98
        #   PRFM     : opc=11 V=0 -> top byte 0xD8
        #   LDR  St  : opc=00 V=1 -> top byte 0x1C
        #   LDR  Dt  : opc=01 V=1 -> top byte 0x5C
        #   LDR  Qt  : opc=10 V=1 -> top byte 0x9C
        top_byte = (val >> 24) & 0xFF
        if top_byte in (0x18, 0x58, 0x98, 0xD8, 0x1C, 0x5C, 0x9C):
            imm19 = (val >> 5) & 0x7FFFF
            if imm19 & 0x40000:  # sign-extend 19 bits
                imm19 -= 0x80000
            literal_ea = ea + (imm19 << 2)
            if nop_start <= literal_ea < nop_end:
                orig_text = _get_disasm(ea)
                _log("  arm64-literal-fix: %s at 0x%X refs pool 0x%X "
                     "(in NOP zone), patching to NOP" %
                     (orig_text, ea, literal_ea))
                _nop_at(ea)
                patched.append((ea, literal_ea, orig_text))
        ea += 4
    return patched


def _collect_original_insns(start, end):
    """Decode instructions from *start* to *end* and return list of
    (addr, length, disasm_text) tuples describing the original code."""
    result = []
    ea = start
    step = _insn_align()  # 4 on ARM64, 1 on x86
    while ea < end:
        insn = ida_ua.insn_t()
        ilen = ida_ua.decode_insn(insn, ea)
        if ilen <= 0:
            ea += step
            continue
        result.append((ea, ilen, _get_disasm(ea)))
        ea += ilen
    return result


def _sign_extend(val, from_bits, to_bits=64):
    """Sign-extend *val* from *from_bits* to *to_bits*."""
    mask = (1 << from_bits) - 1
    val = val & mask
    if val & (1 << (from_bits - 1)):
        val |= ((1 << to_bits) - 1) ^ mask
    return val & ((1 << to_bits) - 1)


def _read_mem(addr, size):
    """Read *size* bytes from the IDB at *addr*. Returns int or None."""
    if size == 1:
        return ida_bytes.get_byte(addr)
    if size == 2:
        return ida_bytes.get_word(addr)
    if size == 4:
        return ida_bytes.get_dword(addr)
    if size == 8:
        return ida_bytes.get_qword(addr)
    return None


def _mop_num(op):
    """Extract numeric value from a mop_n operand. Returns int or None."""
    if op.t != ida_hexrays.mop_n:
        return None
    try:
        return op.nnn.value
    except AttributeError:
        pass
    # Fallback for older / different API revisions
    try:
        return op.value(False)
    except Exception:
        pass
    return None


_MOP_TYPE_NAMES = {
    ida_hexrays.mop_z: "mop_z(none)",
    ida_hexrays.mop_r: "mop_r(reg)",
    ida_hexrays.mop_n: "mop_n(num)",
    ida_hexrays.mop_d: "mop_d(insn)",
    ida_hexrays.mop_S: "mop_S(stk)",
    ida_hexrays.mop_v: "mop_v(global)",
    ida_hexrays.mop_b: "mop_b(blk)",
    ida_hexrays.mop_f: "mop_f(func)",
    ida_hexrays.mop_l: "mop_l(local)",
    ida_hexrays.mop_a: "mop_a(addr)",
    ida_hexrays.mop_h: "mop_h(helper)",
    ida_hexrays.mop_str: "mop_str",
    ida_hexrays.mop_c: "mop_c(case)",
    ida_hexrays.mop_fn: "mop_fn",
    ida_hexrays.mop_p: "mop_p(pair)",
    ida_hexrays.mop_sc: "mop_sc(scat)",
}

def _mop_desc(op):
    """Short description of a mop for logging."""
    tname = _MOP_TYPE_NAMES.get(op.t, "mop_%d" % op.t)
    if op.t == ida_hexrays.mop_n:
        v = _mop_num(op)
        return "%s(0x%X)" % (tname, v) if v is not None else tname
    if op.t == ida_hexrays.mop_r:
        return "%s(r%d, sz=%d)" % (tname, op.r, op.size)
    if op.t == ida_hexrays.mop_S:
        try:
            return "%s(off=%d, sz=%d)" % (tname, op.s.off, op.size)
        except Exception:
            return tname
    if op.t == ida_hexrays.mop_v:
        return "%s(0x%X, sz=%d)" % (tname, op.g, op.size)
    if op.t == ida_hexrays.mop_a:
        try:
            inner = op.a
            return "%s->%s" % (tname, _mop_desc(inner))
        except Exception:
            return tname
    if op.t == ida_hexrays.mop_b:
        return "%s(%d)" % (tname, op.b)
    if op.t == ida_hexrays.mop_d:
        return "%s(sub-insn)" % tname
    return "%s(sz=%d)" % (tname, op.size)


# ---------------------------------------------------------------------------
# Constant-propagation engine (operates on Hex-Rays microcode IR)
# ---------------------------------------------------------------------------

class _PropState(object):
    """Lightweight symbolic state: maps micro-registers and stack slots to
    known constant values.  Also tracks registers that hold stack variable
    addresses (from LEA-like instructions) so that subsequent loads through
    those registers can be resolved."""

    def __init__(self):
        self.regs  = {}   # int(micro_reg) -> int(value)
        self.stack = {}   # int(stkvar_off) -> int(value)
        self.stk_addr_regs = {}  # int(micro_reg) -> int(stk_offset)

    def copy(self):
        s = _PropState()
        s.regs  = dict(self.regs)
        s.stack = dict(self.stack)
        s.stk_addr_regs = dict(self.stk_addr_regs)
        return s

    # -- register helpers --------------------------------------------------
    def set_reg(self, r, val):
        self.regs[r] = val & 0xFFFFFFFFFFFFFFFF
        # If this register held a stack address, the new concrete value
        # replaces it -- remove from stk_addr_regs.
        self.stk_addr_regs.pop(r, None)

    def get_reg(self, r):
        return self.regs.get(r)

    # -- stack address register helpers ------------------------------------
    def set_stk_addr(self, r, stk_off):
        """Record that micro-register *r* holds the ADDRESS of stk[stk_off].
        Also clears any stale concrete value so that ldx through this register
        falls through to the stk_addr resolution path."""
        self.stk_addr_regs[r] = stk_off
        self.regs.pop(r, None)

    def get_stk_addr(self, r):
        """If register *r* holds a stack variable address, return the offset."""
        return self.stk_addr_regs.get(r)

    # -- stack helpers -----------------------------------------------------
    def set_stk(self, off, val):
        self.stack[off] = val & 0xFFFFFFFFFFFFFFFF

    def get_stk(self, off):
        return self.stack.get(off)

    def dump(self):
        parts = []
        for r, v in sorted(self.regs.items()):
            parts.append("r%d=0x%X" % (r, v))
        for r, off in sorted(self.stk_addr_regs.items()):
            parts.append("r%d=&stk[%d]" % (r, off))
        for off, v in sorted(self.stack.items()):
            parts.append("stk[%d]=0x%X" % (off, v))
        return ", ".join(parts) if parts else "(empty)"


# Module-level lookup table for binary arithmetic opcodes used by _eval_insn.
_EVAL_BINOPS = {
    ida_hexrays.m_add: lambda a, b: a + b,
    ida_hexrays.m_sub: lambda a, b: a - b,
    ida_hexrays.m_xor: lambda a, b: a ^ b,
    ida_hexrays.m_and: lambda a, b: a & b,
    ida_hexrays.m_or:  lambda a, b: a | b,
    ida_hexrays.m_mul: lambda a, b: a * b,
    ida_hexrays.m_shl: lambda a, b: a << b,
    ida_hexrays.m_shr: lambda a, b: a >> b,  # logical shift; always positive after & mask
    ida_hexrays.m_udiv: lambda a, b: (a // b) if b else None,
    ida_hexrays.m_sdiv: lambda a, b: (a // b) if b else None,
    ida_hexrays.m_umod: lambda a, b: (a % b) if b else None,
    ida_hexrays.m_smod: lambda a, b: (a % b) if b else None,
}


def _eval_op(op, st):
    """Try to resolve a microcode operand *op* to a concrete integer.
    Returns int or None."""

    t = op.t

    # --- immediate number ---
    if t == ida_hexrays.mop_n:
        return _mop_num(op)

    # --- micro register ---
    if t == ida_hexrays.mop_r:
        return st.get_reg(op.r)

    # --- stack variable ---
    if t == ida_hexrays.mop_S:
        try:
            off = op.s.off
        except Exception:
            return None
        return st.get_stk(off)

    # --- address-of (& operator) ---
    #   e.g.  mov &($loc_D4B0).8, x21.8
    #   The value is the *address* of the inner operand.
    if t == ida_hexrays.mop_a:
        try:
            inner = op.a
            if inner.t == ida_hexrays.mop_v:
                return inner.g          # address of global
            if inner.t == ida_hexrays.mop_S:
                # address of stack var -- we can't resolve to a constant
                return None
        except Exception:
            pass
        return None

    # --- global variable (memory reference) ---
    #   e.g.  $dword_D4C8  --  read the stored value from the binary
    if t == ida_hexrays.mop_v:
        return _read_mem(op.g, op.size)

    # --- sub-instruction result ---
    #   e.g.  xds.8($dword_D4C8.4) embedded inside an add
    if t == ida_hexrays.mop_d:
        return _eval_insn(op.d, st)

    return None


def _eval_insn(insn, st):
    """Try to evaluate a single microcode instruction to a concrete value.
    Returns int or None."""

    opc = insn.opcode

    # -- mov (copy) --------------------------------------------------------
    if opc == ida_hexrays.m_mov:
        return _eval_op(insn.l, st)

    # -- load from memory: ldx seg, addr -> dst ----------------------------
    if opc == ida_hexrays.m_ldx:
        addr = _eval_op(insn.r, st)
        if addr is not None:
            return _read_mem(addr, insn.d.size)
        # Fallback: if the address register holds a stack variable address
        # (from a prior LEA / mov &stk), read the value from our stack state.
        if insn.r.t == ida_hexrays.mop_r:
            stk_off = st.get_stk_addr(insn.r.r)
            if stk_off is not None:
                stk_val = st.get_stk(stk_off)
                if stk_val is not None:
                    mask = (1 << (insn.d.size * 8)) - 1
                    return stk_val & mask
        return None

    # -- sign extend: xds src -> dst ---------------------------------------
    if opc == ida_hexrays.m_xds:
        val = _eval_op(insn.l, st)
        if val is not None:
            return _sign_extend(val, insn.l.size * 8, insn.d.size * 8)
        return None

    # -- zero extend: xdu src -> dst ---------------------------------------
    if opc == ida_hexrays.m_xdu:
        val = _eval_op(insn.l, st)
        if val is not None:
            return val & ((1 << (insn.l.size * 8)) - 1)
        return None

    # -- low: extract low part of operand -----------------------------------
    if opc == ida_hexrays.m_low:
        val = _eval_op(insn.l, st)
        if val is not None:
            return val & ((1 << (insn.d.size * 8)) - 1)
        return None

    # -- high: extract high part of operand ---------------------------------
    if opc == ida_hexrays.m_high:
        val = _eval_op(insn.l, st)
        if val is not None:
            shift = (insn.l.size - insn.d.size) * 8
            if shift > 0:
                return (val >> shift) & ((1 << (insn.d.size * 8)) - 1)
            return val & ((1 << (insn.d.size * 8)) - 1)
        return None

    # -- binary arithmetic: l OP r -> d ------------------------------------
    fn = _EVAL_BINOPS.get(opc)
    if fn is not None:
        lv = _eval_op(insn.l, st)
        rv = _eval_op(insn.r, st)
        if lv is not None and rv is not None:
            result = fn(lv, rv)
            if result is None:
                return None  # e.g. division by zero
            mask = (1 << (insn.d.size * 8)) - 1
            return result & mask
        return None

    # -- arithmetic right shift: sar l, r -> d ------------------------------
    if opc == ida_hexrays.m_sar:
        lv = _eval_op(insn.l, st)
        rv = _eval_op(insn.r, st)
        if lv is not None and rv is not None:
            bits = insn.l.size * 8
            mask = (1 << bits) - 1
            # sign-extend lv to Python int, shift, then mask to dest size
            if lv & (1 << (bits - 1)):
                lv = lv - (1 << bits)  # make negative
            result = lv >> rv
            return result & ((1 << (insn.d.size * 8)) - 1)
        return None

    # -- unary: neg / bnot -------------------------------------------------
    if opc == ida_hexrays.m_neg:
        val = _eval_op(insn.l, st)
        if val is not None:
            mask = (1 << (insn.d.size * 8)) - 1
            return (-val) & mask
        return None

    if opc == ida_hexrays.m_bnot:
        val = _eval_op(insn.l, st)
        if val is not None:
            mask = (1 << (insn.d.size * 8)) - 1
            return (~val) & mask
        return None

    # -- store to memory: stx val, seg, addr --------------------------------
    #    We don't evaluate this but _propagate handles it for stack tracking.
    return None


_OPCODE_NAMES = {}
def _opcode_name(opc):
    """Get readable name for a microcode opcode."""
    if not _OPCODE_NAMES:
        for attr in dir(ida_hexrays):
            if attr.startswith("m_") and not attr.startswith("mop_"):
                try:
                    _OPCODE_NAMES[getattr(ida_hexrays, attr)] = attr
                except Exception:
                    pass
    return _OPCODE_NAMES.get(opc, "m_%d" % opc)


def _propagate(blk, st, stop_at=None, verbose=False, deadline=0):
    """Walk every instruction in *blk* (up to but NOT including *stop_at*)
    and update the propagation state *st*.
    Returns False if aborted by deadline, True otherwise."""

    if deadline and _time.time() > deadline:
        return False
    insn = blk.head
    _n = 0
    while insn is not None:
        if insn == stop_at:
            break
        _n += 1
        if deadline and (_n & 15) == 0 and _time.time() > deadline:
            return False

        opc_name = _opcode_name(insn.opcode) if verbose else ""

        # Evaluate and record destination
        val = _eval_insn(insn, st)

        if verbose:
            dst_desc = _mop_desc(insn.d) if insn.d else "none"
            l_desc = _mop_desc(insn.l) if insn.l else "none"
            r_desc = _mop_desc(insn.r) if insn.r else "none"
            val_str = "0x%X" % val if val is not None else "FAIL"
            _log("    [0x%X] %s  l=%s  r=%s  d=%s  => %s" %
                 (insn.ea, opc_name, l_desc, r_desc, dst_desc, val_str))

        if val is not None:
            dst = insn.d
            if dst.t == ida_hexrays.mop_r:
                st.set_reg(dst.r, val)
            elif dst.t == ida_hexrays.mop_S:
                try:
                    st.set_stk(dst.s.off, val)
                except Exception:
                    pass
        else:
            # Even when _eval_insn returns None, track registers that
            # receive a stack variable ADDRESS (from LEA-like mov &stk, reg).
            # This enables subsequent ldx through these regs to be resolved.
            if insn.opcode == ida_hexrays.m_mov:
                if insn.l.t == ida_hexrays.mop_a:
                    try:
                        inner = insn.l.a
                        if inner.t == ida_hexrays.mop_S and insn.d.t == ida_hexrays.mop_r:
                            st.set_stk_addr(insn.d.r, inner.s.off)
                            if verbose:
                                _log("    -> stk_addr: r%d = &stk[%d]" %
                                     (insn.d.r, inner.s.off))
                    except Exception:
                        pass

        # Also handle stx (store to stack) explicitly:
        if insn.opcode == ida_hexrays.m_stx:
            stored_val = _eval_op(insn.l, st)
            if stored_val is not None:
                dst_addr = insn.d
                if dst_addr.t == ida_hexrays.mop_S:
                    try:
                        st.set_stk(dst_addr.s.off, stored_val)
                        if verbose:
                            _log("    -> stx: stk[%d] = 0x%X" %
                                 (dst_addr.s.off, stored_val))
                    except Exception:
                        pass
                # Also handle store through register that holds a stack
                # address (e.g. lea rax, [rbp+var_48]; mov [rax], 0xA5).
                # The stx destination is the register, not mop_S.
                elif dst_addr.t == ida_hexrays.mop_r:
                    stk_off = st.get_stk_addr(dst_addr.r)
                    if stk_off is not None:
                        st.set_stk(stk_off, stored_val)
                        if verbose:
                            _log("    -> stx via r%d: stk[%d] = 0x%X" %
                                 (dst_addr.r, stk_off, stored_val))

        insn = insn.next
    return True


def _get_preds(blk):
    """Return list of predecessor block serial numbers.

    Uses mblock_t.predset (an intvec_t maintained by the decompiler)
    which is always available once the CFG has been built (MMAT_LOCOPT
    and above).  Falls back to npred()/pred() only if predset iteration
    fails on very old IDA builds.
    """
    # predset is an intvec_t of serial numbers -- preferred method.
    try:
        return list(blk.predset)
    except (AttributeError, TypeError):
        pass
    # Fallback for ancient IDA versions.
    try:
        return [blk.pred(i) for i in range(blk.npred())]
    except (AttributeError, TypeError):
        pass
    return []


# ---------------------------------------------------------------------------
# Opaque-predicate scanner (arch-aware)
# ---------------------------------------------------------------------------

def _is_complementary_jcc_pair(b1, b2):
    """Check if two x86 short-Jcc opcodes form a complementary pair.

    For short Jcc (0x70-0x7F), complementary pairs differ only in the
    lowest bit: jge/jl (0x7D/0x7C), jp/jnp (0x7A/0x7B), etc.
    """
    if not (0x70 <= b1 <= 0x7F and 0x70 <= b2 <= 0x7F):
        return False
    return (b1 ^ b2) == 1


def _is_flag_setter(insn):
    """Return True if *insn* is a flag-setting instruction (CMP, TEST, etc.).

    Uses ``insn.itype`` from ``ida_allins`` so the check is
    architecture-independent -- no raw byte matching needed.
    """
    if not ida_allins:
        return False
    try:
        if _is_arm64():
            return insn.itype in (
                ida_allins.ARM_cmp,    # CMP
                ida_allins.ARM_cmn,    # CMN
                ida_allins.ARM_tst,    # TST
            )
        return insn.itype in (
            ida_allins.NN_cmp,
            ida_allins.NN_test,
        )
    except AttributeError:
        return False


# Pre-built set of x86 conditional-jump itypes (NN_jo .. NN_jg, NN_jnle).
_X86_JCC_ITYPES = None

def _is_jcc_x86(insn):
    """Return True if the decoded *insn* is an x86 conditional jump."""
    global _X86_JCC_ITYPES
    if _X86_JCC_ITYPES is None:
        if ida_allins:
            try:
                _X86_JCC_ITYPES = {
                    ida_allins.NN_jo, ida_allins.NN_jno,
                    ida_allins.NN_jb, ida_allins.NN_jnb,
                    ida_allins.NN_jz, ida_allins.NN_jnz,
                    ida_allins.NN_jbe, ida_allins.NN_ja,
                    ida_allins.NN_js, ida_allins.NN_jns,
                    ida_allins.NN_jp, ida_allins.NN_jnp,
                    ida_allins.NN_jl, ida_allins.NN_jge,
                    ida_allins.NN_jle, ida_allins.NN_jg,
                }
            except AttributeError:
                _X86_JCC_ITYPES = set()
        else:
            _X86_JCC_ITYPES = set()
    return insn.itype in _X86_JCC_ITYPES


def _jcc_complementary_x86(insn1, insn2):
    """Check if two x86 Jcc instructions form a complementary pair.

    Complementary means they test opposite conditions (e.g. JGE vs JL).
    In ida_allins, complementary Jcc pairs have itypes that differ by 1:
    NN_jo/NN_jno, NN_jb/NN_jnb, NN_jz/NN_jnz, etc.
    """
    return abs(insn1.itype - insn2.itype) == 1


def _scan_opaque_preds_x86(target_addr):
    """x86: scan forward from *target_addr* past CMP/TEST+Jcc opaque preds.

    Uses ``decode_insn`` + ``ida_allins`` instruction IDs instead of raw
    byte matching -- architecture-aware via the processor module.

    Returns ``(real_addr, pred_list)`` where *pred_list* contains
    ``(start, end, cmp_disasm, jcc_disasm)`` for each detected pair.
    """
    addr = target_addr
    count = 0
    pred_list = []

    while count < 5:
        insn = ida_ua.insn_t()
        ilen = ida_ua.decode_insn(insn, addr)
        if ilen <= 0:
            break

        if not _is_flag_setter(insn):
            break

        jcc_addr = addr + ilen
        insn2 = ida_ua.insn_t()
        ilen2 = ida_ua.decode_insn(insn2, jcc_addr)
        if ilen2 <= 0:
            break

        if not _is_jcc_x86(insn2):
            break

        cmp_text = _get_disasm(addr)
        jcc_text = _get_disasm(jcc_addr)
        pred_list.append((addr, jcc_addr + ilen2, cmp_text, jcc_text))

        _log("  opaque-pred-x86: CMP/TEST+Jcc at 0x%X (%d+%d bytes)" %
             (addr, ilen, ilen2))
        addr = jcc_addr + ilen2
        count += 1

    return addr, pred_list


def _decode_bcond_arm64(ea, precomputed_insn=None):
    """Decode an ARM64 B.cond instruction at *ea*.

    Returns ``(cond, target)`` or ``None`` if not a B.cond.

    When *precomputed_insn* is given (an ``insn_t`` already decoded at *ea*),
    the condition code is read from ``insn.segpref`` (the ARM processor
    module stores the 4-bit condition in this field) and the branch target
    from operand 0.  This avoids raw byte parsing.

    Falls back to raw encoding when *precomputed_insn* is not provided —
    this path is used by ``_clean_junk_in_func_range_arm64`` which must
    NOT call ``decode_insn`` (safe only in optimizer callbacks).

    B.cond encoding: 01010100 imm19 0 cond  (bits[31:24]=0x54, bit[4]=0)
    """
    if precomputed_insn is not None:
        # Use IDA's decoded instruction fields
        insn = precomputed_insn
        if ida_allins and insn.itype == ida_allins.ARM_b:
            cond = insn.segpref  # ARM module stores condition in segpref
            if cond >= 14:
                return None      # AL(14)/NV(15) = unconditional, not B.cond
            # Branch target from first operand
            try:
                target = insn.Op1.addr
            except (AttributeError, TypeError):
                target = insn.ops[0].addr
            return (cond, target)
        return None  # not a branch instruction

    # Raw encoding fallback (no decode_insn needed — byte-level safe)
    val = _read_u32_le(ea)
    if (val & 0xFF000010) != 0x54000000:
        return None
    cond = val & 0xF
    imm19 = (val >> 5) & 0x7FFFF
    if imm19 & 0x40000:  # sign-extend 19-bit
        imm19 -= 0x80000
    target = ea + (imm19 << 2)
    return (cond, target)


def _scan_opaque_preds_arm64(target_addr):
    """ARM64: scan forward from *target_addr* past CMP + B.cond opaque preds.

    Uses ``decode_insn`` + ``ida_allins`` for both flag-setter detection
    (CMP, CMN, TST) and B.cond decoding.  The condition code is read from
    ``insn.segpref`` (ARM processor module convention) instead of raw
    byte parsing.

    Returns ``(real_addr, pred_list)`` matching the x86 function signature.
    """
    addr = target_addr
    count = 0
    pred_list = []

    while count < 5:
        insn = ida_ua.insn_t()
        ilen = ida_ua.decode_insn(insn, addr)
        if ilen != 4:
            break

        # Detect CMP / CMN / TST via processor module (architecture-aware)
        if not _is_flag_setter(insn):
            break

        # Next instruction must be B.cond — use decode_insn + segpref
        bcond_addr = addr + 4
        insn2 = ida_ua.insn_t()
        if ida_ua.decode_insn(insn2, bcond_addr) != 4:
            break
        bc = _decode_bcond_arm64(bcond_addr, precomputed_insn=insn2)
        if bc is None:
            break

        cmp_text = _get_disasm(addr)
        jcc_text = _get_disasm(bcond_addr)
        pred_list.append((addr, bcond_addr + 4, cmp_text, jcc_text))

        _log("  opaque-pred-arm64: CMP+B.cond at 0x%X (4+4 bytes)" % addr)
        addr = bcond_addr + 4
        count += 1

    return addr, pred_list


def _scan_opaque_preds(target_addr):
    """Arch-dispatching wrapper for opaque predicate scanning."""
    if _is_arm64():
        return _scan_opaque_preds_arm64(target_addr)
    return _scan_opaque_preds_x86(target_addr)


def _clean_junk_in_func_range(func_start, func_end):
    """Scan a function range for complementary conditional branch pairs
    (opaque predicates) and NOP the dead-code bytes via patch_byte.

    IMPORTANT: This function uses ONLY ida_bytes.get_byte / patch_byte.
    It must NOT call decode_insn, del_items, or create_insn because those
    can trigger IDA processor-module notifications that deadlock when
    called from certain contexts (timer callbacks after auto_wait).

    Safe to call from: optimizer callback (optblock_t.func).
    NOT safe to call from: timer callbacks after auto_wait().

    Returns the number of opaque predicates cleaned.
    """
    if _is_arm64():
        return _clean_junk_in_func_range_arm64(func_start, func_end)
    return _clean_junk_in_func_range_x86(func_start, func_end)


def _clean_junk_in_func_range_x86(func_start, func_end):
    """x86: scan for complementary short-Jcc pairs."""
    cleaned = 0
    ea = func_start

    while ea < func_end - 3:
        b0 = ida_bytes.get_byte(ea)

        if not (0x70 <= b0 <= 0x7F):
            ea += 1
            continue

        ea2 = ea + 2
        if ea2 >= func_end:
            break
        b1 = ida_bytes.get_byte(ea2)

        if not _is_complementary_jcc_pair(b0, b1):
            ea += 1
            continue

        d0 = ida_bytes.get_byte(ea + 1)
        if d0 >= 0x80:
            d0 -= 0x100
        t0 = ea + 2 + d0

        d1 = ida_bytes.get_byte(ea2 + 1)
        if d1 >= 0x80:
            d1 -= 0x100
        t1 = ea2 + 2 + d1

        if t0 != t1:
            ea += 1
            continue

        dead_start = ea2 + 2
        dead_end = t0

        if dead_start < dead_end and dead_end <= func_end:
            # Skip if dead zone is already NOP'd (idempotency)
            already_clean = all(ida_bytes.get_byte(a) == 0x90
                                for a in range(dead_start, dead_end))
            if not already_clean:
                _log("  clean-junk-x86: Jcc pair at 0x%X/0x%X, "
                     "NOP dead zone [0x%X-0x%X), target=0x%X" %
                     (ea, ea2, dead_start, dead_end, t0))
                _nop_range(dead_start, dead_end)
                cleaned += 1

        ea = dead_end if dead_end > ea else ea + 1

    if cleaned:
        _log("  clean-junk-x86: cleaned %d opaque pred(s) in [0x%X-0x%X)" %
             (cleaned, func_start, func_end))
    return cleaned


def _clean_junk_in_func_range_arm64(func_start, func_end):
    """ARM64: scan for complementary B.cond pairs."""
    cleaned = 0
    ea = func_start

    while ea < func_end - 7:  # need 8 bytes for two B.cond
        bc0 = _decode_bcond_arm64(ea)
        if bc0 is None:
            ea += 4
            continue

        bc1 = _decode_bcond_arm64(ea + 4)
        if bc1 is None:
            ea += 4
            continue

        cond0, target0 = bc0
        cond1, target1 = bc1

        # Complementary: differ only in lowest bit (EQ/NE, LT/GE, etc.)
        if (cond0 ^ cond1) != 1 or target0 != target1:
            ea += 4
            continue

        dead_start = ea + 8
        dead_end = target0

        if dead_start < dead_end and dead_end <= func_end:
            # ARM64 NOP = D503201F (4 bytes LE: 1F 20 03 D5)
            already_clean = all(
                _read_u32_le(a) == 0xD503201F
                for a in range(dead_start, dead_end, 4))
            if not already_clean:
                _log("  clean-junk-arm64: B.cond pair at 0x%X, "
                     "NOP dead zone [0x%X-0x%X), target=0x%X" %
                     (ea, dead_start, dead_end, target0))
                _nop_range(dead_start, dead_end)
                cleaned += 1
            ea = dead_end
        else:
            ea += 4

    if cleaned:
        _log("  clean-junk-arm64: cleaned %d opaque pred(s) in [0x%X-0x%X)" %
             (cleaned, func_start, func_end))
    return cleaned


def _find_func_end_from_mba(mba, target_addr):
    """Scan the microcode block array for ``m_ret`` instructions to locate
    the function end.  This is architecture-independent -- ``m_ret`` is
    the same opcode on x86, ARM64, MIPS, etc.

    Returns the binary address just past the last RET found after
    *target_addr*, or 0 if none is found.  Also checks for tail-call
    patterns (``BLT_1WAY`` goto to an external address or a prologue).
    """
    best_end = 0
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        # Skip blocks that are before the target
        if blk.end <= target_addr:
            continue
        # Check if block's tail is m_ret
        if blk.tail is not None and blk.tail.opcode == ida_hexrays.m_ret:
            # blk.end is the address right after the last instruction
            candidate = blk.end
            if candidate > best_end:
                best_end = candidate
                _log("  mba-ret-scan: found m_ret in block %d, "
                     "func_end candidate = 0x%X" % (i, candidate))
    return best_end


# ---------------------------------------------------------------------------
# IDB fixup helpers (for use in timer callbacks only)
# ---------------------------------------------------------------------------

def _make_code_region(start, end):
    """Clear stale data items in [start, end) and re-create as code.

    Calls ``del_items`` then ``create_insn`` in a loop.  Must only be
    called from a timer callback (NOT from an optimizer callback).
    """
    step = _insn_align()
    ida_bytes.del_items(start, ida_bytes.DELIT_SIMPLE, end - start)
    ea = start
    while ea < end:
        cl = ida_ua.create_insn(ea)
        ea += max(cl, step)


def _ensure_func_at(start, end, name=None):
    """Ensure a function exists at [start, end).

    If the address is covered by a different function, splits it first.
    Optionally restores *name* if it's non-trivial.  Must only be called
    from a timer callback.
    """
    existing = ida_funcs.get_func(start)
    if existing is not None and existing.start_ea == start:
        return  # already correct
    if existing and existing.start_ea != start:
        ida_funcs.del_func(existing.start_ea)
        ida_funcs.add_func(existing.start_ea, start)
    _make_code_region(start, end)
    ida_funcs.add_func(start, end)
    if name and not name.startswith("sub_"):
        ida_name.set_name(start, name,
                          ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
    _log("  ensure-func: [0x%X-0x%X) %s" % (start, end, name or ""))


def _repair_swallowed_prologues(region_starts):
    """Scan functions near *region_starts* for internal prologues that
    indicate a swallowed adjacent function.  Split at each prologue.

    Call after ``auto_wait()`` when IDA auto-analysis may have created
    functions with over-extended boundaries (e.g. extending past a
    BL-to-noreturn into the next function's prologue).

    Returns the number of repairs made.
    """
    step = _insn_align()
    repaired = 0
    checked = set()

    for r_ea in region_starts:
        func = ida_funcs.get_func(r_ea)
        if func is None:
            continue
        # Check the auto-created function right after this one too
        candidates = [func]
        nf = ida_funcs.get_next_func(func.end_ea - 1)
        if nf is not None:
            candidates.append(nf)

        for f in candidates:
            f_start = f.start_ea
            f_end = f.end_ea
            if f_start in checked:
                continue
            checked.add(f_start)
            # Skip small functions (< 32 bytes can't meaningfully
            # contain a swallowed prologue)
            if f_end - f_start < 32:
                continue
            # Scan for prologues inside the function, starting after
            # the first few instructions (to skip its own prologue).
            scan_ea = f_start + step * 4
            while scan_ea < f_end:
                if _is_prologue_at(scan_ea):
                    ida_funcs.del_func(f_start)
                    ida_funcs.add_func(f_start, scan_ea)
                    ida_funcs.add_func(scan_ea)
                    _log("  boundary-repair: split 0x%X at prologue 0x%X "
                         "(was 0x%X-0x%X)" %
                         (f_start, scan_ea, f_start, f_end))
                    repaired += 1
                    break
                scan_ea += step
    return repaired


def _extend_tiny_prologue_funcs():
    """Scan all functions for tiny prologue-only boundaries (< 0x20 bytes)
    that decompile with JUMPOUT.  Extend each by scanning forward for
    the real function end (RET or next prologue).

    On x86_64, computed-branch obfuscation often causes IDA to create a
    very small function covering only the prologue (push rbp; mov rbp,
    rsp; ...).  The real function body — including the indirect jump —
    lives outside the boundary, invisible to the microcode optimizer.

    This function extends those boundaries so the next decompilation
    pass can see the indirect jump and resolve it.

    Returns ``(count, extended_eas)`` — count and set of extended EAs.
    """
    nfuncs = ida_funcs.get_func_qty()
    extended = 0
    extended_eas = set()
    MAX_TINY = 0x40  # functions smaller than this are candidates

    for i in range(nfuncs):
        func = ida_funcs.getn_func(i)
        if func is None:
            continue
        f_start = func.start_ea
        f_end = func.end_ea
        f_size = f_end - f_start
        if f_size >= MAX_TINY:
            continue

        # Skip large jump tables — extending them causes the
        # decompiler's CLP solver to hang.
        if _has_large_jump_table(f_start, f_end):
            _log("  extend-tiny: 0x%X is large jump table (%d bytes), skipping"
                 % (f_start, f_size))
            continue

        # Skip functions that already timed out in a prior pass.
        if f_start in _g_timeout_funcs:
            continue

        # Quick check: does this decompile with JUMPOUT?
        cfunc, _to = _decompile_with_timeout(f_start)
        if _to or (_g_optimizer and _g_optimizer._timed_out):
            _g_timeout_funcs.add(f_start)
            continue
        if cfunc is None or 'JUMPOUT' not in str(cfunc):
            continue

        # Scan forward from function end for the real end
        new_end = _scan_for_func_end(f_end)
        if new_end == 0:
            continue
        new_size = new_end - f_start
        if new_size > 0x10000:
            continue  # sanity: don't create absurdly large functions

        # Check for neighboring functions that would be swallowed
        nf = ida_funcs.get_next_func(f_start)
        absorbed_nf = False
        if nf is not None and nf.start_ea < new_end:
            # If the adjacent function starts exactly at our end AND a
            # JUMPOUT target from the tiny function lands inside the
            # adjacent function, the adjacent function is really the
            # body that was split off by obfuscation — absorb it.
            if nf.start_ea == f_end:
                import re as _re
                jumpout_targets = set()
                try:
                    cftext = str(cfunc) if cfunc else ""
                    for m in _re.finditer(r'JUMPOUT\s*\(\s*0x([0-9A-Fa-f]+)', cftext):
                        jumpout_targets.add(int(m.group(1), 16))
                except Exception:
                    pass
                nf_start = nf.start_ea
                nf_end_ea = nf.end_ea
                target_in_adj = any(nf_start <= t < nf_end_ea
                                    for t in jumpout_targets)
                if target_in_adj:
                    # Cap new_end at the neighbor's end if needed
                    if new_end < nf_end_ea:
                        new_end = nf_end_ea
                    # Check for yet another neighbor after the absorbed one
                    nf2 = ida_funcs.get_next_func(nf_start)
                    if nf2 is not None and nf2.start_ea < new_end:
                        new_end = nf2.start_ea
                    ida_funcs.del_func(nf_start)
                    absorbed_nf = True
                    _log("  extend-tiny: absorbed adjacent func 0x%X "
                         "[0x%X-0x%X) (JUMPOUT target inside)"
                         % (nf_start, nf_start, nf_end_ea))
            if not absorbed_nf:
                new_end = nf.start_ea  # cap at neighbor
                if new_end <= f_end:
                    continue  # can't extend

        # Extend: delete old, create code, add new
        ida_funcs.del_func(f_start)
        _make_code_region(f_start, new_end)
        ida_funcs.add_func(f_start, new_end)
        _log("  extend-tiny: 0x%X extended [0x%X-0x%X) -> [0x%X-0x%X)" %
             (f_start, f_start, f_end, f_start, new_end))
        extended += 1
        extended_eas.add(f_start)

    return extended, extended_eas


def _repair_jumpout_boundaries():
    """Phase 5: repair function boundaries for JUMPOUT functions.

    Scans all functions for JUMPOUT in decompiled output.  When the
    JUMPOUT target is at or just past the function boundary (and not
    inside another function), extends the boundary to the real function
    end (next RET or prologue).

    When the JUMPOUT target lands inside an adjacent function whose
    only inbound references come from the current function, the adjacent
    function is absorbed (deleted and merged).

    Returns ``(repaired_starts, n_total)`` — set of repaired function
    start addresses and total count of boundary repairs.
    """
    import re as _re

    nfuncs = ida_funcs.get_func_qty()
    repaired = set()

    for i in range(nfuncs):
        func = ida_funcs.getn_func(i)
        if func is None:
            continue
        f_start = func.start_ea
        f_end = func.end_ea

        if f_start in _g_timeout_funcs:
            continue

        # Decompile and check for JUMPOUT
        cfunc, _to = _decompile_with_timeout(
            f_start, flags=ida_hexrays.DECOMP_NO_WAIT)
        if _to or (_g_optimizer and _g_optimizer._timed_out):
            _g_timeout_funcs.add(f_start)
            continue
        if cfunc is None:
            continue
        txt = str(cfunc)
        if 'JUMPOUT' not in txt:
            continue

        # Extract JUMPOUT target addresses
        targets = set()
        for m in _re.finditer(r'JUMPOUT\s*\(\s*0x([0-9A-Fa-f]+)', txt):
            targets.add(int(m.group(1), 16))

        if not targets:
            continue

        # Filter: only targets that are outside the function but close
        outside = [t for t in targets
                   if t >= f_end and t < f_end + 0x1000 and t < 0x7FFFFFFF]
        if not outside:
            continue

        max_target = max(outside)

        # Check if the target is in an adjacent function
        nf = ida_funcs.get_next_func(f_start)
        absorbed = False
        if nf is not None and nf.start_ea <= max_target < nf.end_ea:
            # Target is inside the next function — check if safe to absorb
            import ida_xref as _xr
            only_from_us = True
            xr = _xr.get_first_cref_to(nf.start_ea)
            while xr != 0xFFFFFFFFFFFFFFFF:
                if xr < f_start or xr >= f_end:
                    only_from_us = False
                    break
                xr = _xr.get_next_cref_to(nf.start_ea, xr)
            if only_from_us:
                new_end = nf.end_ea
                nf2 = ida_funcs.get_next_func(nf.start_ea)
                if nf2 is not None and nf2.start_ea < new_end:
                    new_end = nf2.start_ea
                ida_funcs.del_func(nf.start_ea)
                absorbed = True
                _log("  boundary-repair: absorbed adj 0x%X into 0x%X"
                     % (nf.start_ea, f_start))
            else:
                continue  # can't absorb — target is in an independent func

        if not absorbed:
            # Target is not in any function — extend our boundary
            new_end = _scan_for_func_end(f_end)
            if not new_end or new_end <= f_end:
                new_end = max_target + 0x20  # fallback: past the target
            # Cap at next function
            nf = ida_funcs.get_next_func(f_start)
            if nf is not None and nf.start_ea < new_end:
                new_end = nf.start_ea
            if new_end <= f_end:
                continue

        # Rebuild the function
        ida_funcs.del_func(f_start)
        _make_code_region(f_start, new_end)
        ida_funcs.add_func(f_start, new_end)
        repaired.add(f_start)
        _log("  boundary-repair: 0x%X [0x%X-0x%X) -> [0x%X-0x%X)"
             % (f_start, f_start, f_end, f_start, new_end))

    return repaired, len(repaired)


def _clean_standalone_opaque_preds():
    """Phase 4: clean standalone opaque predicates in all functions.

    Scans every function for complementary Jcc pairs (opaque predicates)
    that were NOT cleaned during Phase 2 (computed-branch auto-patching).
    These are standalone obfuscation constructs — two adjacent conditional
    jumps to the same target with junk bytes in the dead zone between the
    pair and the target.

    NOP the junk bytes (via ``patch_byte``, always safe), then rebuild IDB
    items (``del_items`` + ``create_insn`` + ``del_func``/``add_func``).

    This runs from the main thread (NOT from an optimizer callback), so
    all IDB-modifying APIs are safe.

    Returns ``(affected_starts, n_preds)`` where *affected_starts* is a
    set of function start addresses that were rebuilt, and *n_preds* is
    the total number of opaque predicates cleaned.
    """
    nfuncs = ida_funcs.get_func_qty()
    total_preds = 0
    affected = []  # (f_start, old_f_end) for functions with cleaned junk

    for i in range(nfuncs):
        func = ida_funcs.getn_func(i)
        if func is None:
            continue
        f_start = func.start_ea
        f_end = func.end_ea

        # Skip functions in the timeout skip-list (e.g. large jump tables
        # that cause expensive auto-analysis when their boundaries change).
        if f_start in _g_timeout_funcs:
            continue

        # Skip large jump tables — extending their boundaries causes
        # the decompiler's CLP solver to hang.
        if _has_large_jump_table(f_start, f_end):
            continue

        # Scan with generous range beyond the function boundary to catch
        # junk bytes that IDA left outside due to analysis failure at the
        # opaque predicate.
        scan_end = max(f_end, f_start + 0x100) + 0x100

        # Cap at next function + small margin to reduce false-positive risk
        # in unrelated code.
        nf = ida_funcs.get_next_func(f_start)
        if nf is not None:
            scan_end = min(scan_end, nf.start_ea + 0x20)

        n = _clean_junk_in_func_range(f_start, scan_end)
        if n > 0:
            total_preds += n
            affected.append((f_start, f_end))

    if not affected:
        return set(), 0

    _log("opaque-phase4: NOP'd %d opaque pred(s) in %d function(s), "
         "rebuilding IDB..." % (total_preds, len(affected)))

    # Rebuild IDB for affected functions
    affected_starts = set()
    for (f_start, old_end) in affected:
        new_end = _scan_for_func_end(f_start)
        if not new_end or new_end <= f_start:
            new_end = old_end

        # Cap at next function to avoid swallowing neighbors
        nf = ida_funcs.get_next_func(f_start)
        if nf is not None and nf.start_ea > f_start and nf.start_ea < new_end:
            new_end = nf.start_ea

        try:
            ida_funcs.del_func(f_start)
        except Exception:
            pass
        _make_code_region(f_start, new_end)
        ida_funcs.add_func(f_start, new_end)
        affected_starts.add(f_start)
        _log("  opaque-phase4: rebuilt 0x%X [0x%X-0x%X) (was -0x%X)"
             % (f_start, f_start, new_end, old_end))

    return affected_starts, total_preds


# ---------------------------------------------------------------------------
# Main optimizer callback
# ---------------------------------------------------------------------------

class _DeferredFixup(object):
    """Data holder for a single deferred IDB fixup.

    Inside an optblock_t callback it is unsafe to modify IDB items
    (del_items, create_insn) or functions (del_func, add_func) because
    the decompiler holds internal references to them.  Fixups are
    collected into a module-level queue and processed in a single
    timer callback to avoid the timer-storm that occurs when many
    functions are decompiled in batch."""

    def __init__(self, ijmp_ea, target_addr, func_start,
                 orig_ijmp_text, junk_insns, opaque_preds,
                 adj_func_info=None,
                 literal_load_patches=None, mba_func_end=0):
        self.ijmp_ea = ijmp_ea
        self.target_addr = target_addr
        self.func_start = func_start
        self.orig_ijmp_text = orig_ijmp_text
        self.junk_insns = junk_insns
        self.opaque_preds = opaque_preds
        self.adj_func_info = adj_func_info
        self.literal_load_patches = literal_load_patches or []
        self.mba_func_end = mba_func_end


# -- Batched fixup queue & single-timer dispatcher -------------------------

_g_fixup_queue = []      # list of _DeferredFixup
_g_fixup_timer = None    # ida_kernwin timer id (or None)


def _schedule_fixup(fixup):
    """Add *fixup* to the queue and ensure the batch timer is running."""
    global _g_fixup_timer
    _g_fixup_queue.append(fixup)
    if _g_fixup_timer is None:
        _g_fixup_timer = ida_kernwin.register_timer(100, _run_fixup_batch)


def _run_fixup_batch():
    """Timer callback: drain the entire fixup queue in one shot.

    All IDB-modifying operations (del_items, create_insn, add_func) are
    performed without any auto_wait() calls — IDA's background
    auto-analysis will catch up asynchronously.  This keeps the UI
    responsive even when hundreds of fixups are queued."""
    global _g_fixup_timer
    n = len(_g_fixup_queue)
    if n == 0:
        _g_fixup_timer = None
        return -1                       # nothing to do, unregister

    _log("fixup-batch: processing %d queued fixups" % n)
    batch = list(_g_fixup_queue)
    _g_fixup_queue.clear()

    for idx, fix in enumerate(batch):
        try:
            _apply_single_fixup(fix)
        except Exception as e:
            _log("  fixup-batch[%d] FAILED (0x%X): %s" %
                 (idx, fix.ijmp_ea, str(e)))
            traceback.print_exc()

    # No auto_wait — let IDA's background analysis run asynchronously.
    # The user (or a script) should call ida_auto.auto_wait() explicitly
    # if they need all analysis to be complete before proceeding.
    _log("fixup-batch: done (%d fixups applied, auto-analysis in background)" % n)

    # If more fixups were enqueued during processing, keep the timer
    if _g_fixup_queue:
        return 100                      # reschedule in 100 ms
    _g_fixup_timer = None
    return -1                           # unregister


def _apply_single_fixup(fix):
    """Execute one deferred fixup (no auto_wait inside)."""
    ijmp_ea = fix.ijmp_ea
    target_addr = fix.target_addr
    func_start = fix.func_start

    # ---- Convert patched bytes to code instructions ----
    _make_code_region(ijmp_ea, target_addr)

    # ---- Fix function boundary ----
    ida_ua.create_insn(target_addr)

    # Determine function end
    func_end = fix.mba_func_end
    if func_end:
        _log("  fixup 0x%X: mba-derived func_end = 0x%X" %
             (ijmp_ea, func_end))
    else:
        func_end = _scan_for_func_end(target_addr)

    if not func_end:
        func_end = target_addr + 0x100
        _log("  fixup 0x%X: WARNING ret not found, "
             "using fallback end 0x%X" % (ijmp_ea, func_end))

    # ---- Collect ALL neighboring functions before del_func ----
    # When func_end overshoots into a neighboring function, truncate
    # to prevent swallowing it.  We scan for every function whose
    # start lies in (func_start, func_end] so we can cap func_end
    # at the first one and restore any that get damaged.
    neighbors = []  # list of (start, end, name)
    _scan_ea = func_start
    while True:
        _nf = ida_funcs.get_next_func(_scan_ea)
        if _nf is None or _nf.start_ea > func_end:
            break
        if _nf.start_ea > func_start:
            neighbors.append((_nf.start_ea, _nf.end_ea,
                              ida_funcs.get_func_name(_nf.start_ea) or ""))
        _scan_ea = _nf.start_ea

    # Also include the function exactly at func_end (the "next" one)
    _nf_at_end = ida_funcs.get_func(func_end)
    if (_nf_at_end is not None and _nf_at_end.start_ea == func_end
            and not any(n[0] == func_end for n in neighbors)):
        neighbors.append((_nf_at_end.start_ea, _nf_at_end.end_ea,
                          ida_funcs.get_func_name(_nf_at_end.start_ea) or ""))

    # Include adj_func_info from the optimizer callback (detected via
    # prologue scan during Phase 2.5, may not exist as a function yet)
    if fix.adj_func_info:
        adj_s, adj_e = fix.adj_func_info
        if adj_s > func_start and not any(n[0] == adj_s for n in neighbors):
            neighbors.append((adj_s, adj_e, ""))

    neighbors.sort(key=lambda t: t[0])

    # Cap func_end at the first neighboring function to prevent
    # add_func from swallowing adjacent functions.
    if neighbors:
        first_nb = neighbors[0][0]
        if first_nb < func_end:
            _log("  fixup 0x%X: capping func_end 0x%X -> 0x%X "
                 "(protecting %d neighbor(s), first at 0x%X)" %
                 (ijmp_ea, func_end, first_nb,
                  len(neighbors), first_nb))
            func_end = first_nb

    try:
        ida_funcs.del_func(func_start)
    except Exception:
        pass

    # Re-create the main function (no auto_wait here)
    _make_code_region(func_start, func_end)
    ida_funcs.add_func(func_start, func_end)
    _log("  fixup 0x%X: function re-created [0x%X-0x%X)" %
         (ijmp_ea, func_start, func_end))

    # ---- Restore ALL neighboring functions that might be damaged ----
    for (nb_start, nb_end, nb_name) in neighbors:
        _ensure_func_at(nb_start, nb_end, nb_name)

    # ---- Annotate patched locations ----
    ida_bytes.set_cmt(ijmp_ea,
        "[deobf] was: %s | resolved target -> 0x%X" %
        (fix.orig_ijmp_text, target_addr), 0)

    for (cmt_ea, _ilen, disasm) in fix.junk_insns:
        ida_bytes.set_cmt(cmt_ea,
            "[deobf] NOP'd junk: was: %s" % disasm, 0)

    for (pred_start, pred_end, cmp_text, jcc_text) in fix.opaque_preds:
        ida_bytes.set_cmt(pred_start,
            "[deobf] NOP'd opaque pred: was: %s ; %s" %
            (cmp_text, jcc_text), 0)

    for (lit_ea, pool_ea, orig_text) in fix.literal_load_patches:
        ida_bytes.set_cmt(lit_ea,
            "[deobf] NOP'd literal load: was: %s (pool @ 0x%X)" %
            (orig_text, pool_ea), 0)


class CBDeobfOptimizer(ida_hexrays.optblock_t):
    """Hex-Rays microcode block optimizer that resolves computed indirect
    jumps produced by computed-branch obfuscation.

    Registered at MMAT_LOCOPT.  For every block ending with m_ijmp,
    attempts constant propagation to determine the jump target and
    replaces the ijmp with a direct goto."""

    DECOMPILE_TIMEOUT = 3.0  # seconds; 0 = no timeout

    def __init__(self):
        ida_hexrays.optblock_t.__init__(self)
        self.total_resolved = 0
        self._patched_addrs = set()  # avoid re-patching the same ijmp
        self._deadline = 0           # set by fix_all before each decompile()
        self._timed_out = False      # set when deadline exceeded
        self._func_calls = 0        # callback invocation count per decompile

    # ------------------------------------------------------------------
    # Auto-patch: when the ijmp target is outside the function, patch
    # the binary (JMP reg -> JMP direct).  IDB fixups (del_items,
    # create_insn, del_func, add_func) are DEFERRED via a timer so
    # they run after the decompiler has finished -- doing them inside
    # the optimizer callback causes INTERR.
    # ------------------------------------------------------------------
    def _auto_patch_ijmp(self, mba, blk, tail_insn, target_addr):
        """Patch the indirect JMP at binary level and schedule a deferred
        fixup for IDB items and function boundaries."""
        ijmp_ea = tail_insn.ea
        if ijmp_ea in self._patched_addrs:
            return False  # already patched in a prior call

        func_start = mba.entry_ea

        # Sanity check: target must be within 64KB of the function.
        # Bogus propagation results (e.g. 0x5644BA07 for a function at
        # 0x21068) would cause _collect_original_insns to iterate over
        # billions of addresses.
        MAX_PATCH_DIST = 0x10000  # 64 KB
        if abs(target_addr - func_start) > MAX_PATCH_DIST:
            _log("  auto-patch: target 0x%X too far from func 0x%X (dist=0x%X), skipping"
                 % (target_addr, func_start, abs(target_addr - func_start)))
            return False

        # Only mark as patched AFTER validation passes, so a later
        # maturity level with the correct target can still try.
        self._patched_addrs.add(ijmp_ea)

        # Decode the original instruction to get its length
        insn_len = ida_ua.decode_insn(ida_ua.insn_t(), ijmp_ea)
        if insn_len <= 0:
            if _is_arm64():
                insn_len = 4  # ARM64 instructions are always 4 bytes
            else:
                b0 = ida_bytes.get_byte(ijmp_ea)
                if b0 == 0x41:
                    insn_len = 3
                elif b0 == 0xFF:
                    insn_len = 2
                else:
                    _log("  auto-patch: cannot determine instruction length at 0x%X" % ijmp_ea)
                    return False

        # ---- Phase 1: collect original disassembly BEFORE any patching ----
        orig_ijmp_text = _get_disasm(ijmp_ea)

        raw_target = target_addr
        real_target, opaque_preds = _scan_opaque_preds(target_addr)
        if real_target != target_addr:
            _log("  auto-patch: opaque preds at 0x%X..0x%X, real code at 0x%X" %
                 (target_addr, real_target, real_target))
            target_addr = real_target

        nop_start = ijmp_ea + insn_len
        junk_insns = _collect_original_insns(nop_start, raw_target)

        _log("  auto-patch: ijmp at 0x%X, len=%d, target=0x%X" %
             (ijmp_ea, insn_len, target_addr))

        # ---- Phase 2: binary patching (patch_byte is safe in callbacks) ---
        if not _patch_direct_branch(ijmp_ea, target_addr, insn_len):
            _log("  auto-patch: failed to encode direct branch at 0x%X" %
                 ijmp_ea)
            return False
        _log("  auto-patch: patched direct branch 0x%X -> 0x%X" %
             (ijmp_ea, target_addr))

        # NOP everything between end-of-branch and the real target
        branch_size = 4 if _is_arm64() else min(insn_len, 5 if insn_len >= 5 else 2)
        nop_from = ijmp_ea + insn_len  # after original instruction
        if nop_from < target_addr:
            _nop_range(nop_from, target_addr)
            _log("  auto-patch: NOP'd [0x%X-0x%X)" %
                 (nop_from, target_addr))

        # ---- Phase 2a: NOP ARM64 LDR-literal instructions that reference
        #      the junk zone.  Their literal-pool entries become DCD data
        #      items that block code creation during function
        #      reconstruction.  We also scan a small region AFTER the
        #      junk zone because some literal pools are placed past the
        #      branch target.  Patching is safe here (optimizer callback).
        literal_load_patches = _nop_arm64_literal_loads(
            func_start, target_addr,   # scan code zone + junk zone
            nop_from, target_addr)      # literal pool must be in NOP zone

        # ---- Phase 2b: NOP dead computation chains whose literal-pool
        #      load was just destroyed.  When a LDRSW in the code zone
        #      (before the branch) gets NOP'd, the arithmetic chain that
        #      depended on it is dead code.  If the chain writes to the
        #      original branch register (typically X8, the ARM64 indirect
        #      result register), the decompiler may treat the garbage
        #      value as a function-call argument.  NOP the chain from the
        #      destroyed literal load to the (now patched) branch.
        if _is_arm64() and literal_load_patches:
            for (lit_ea, _pool_ea, _orig_text) in literal_load_patches:
                if lit_ea >= ijmp_ea:
                    continue  # not in the computation chain for this branch
                # Also NOP the ADR/ADRP before the destroyed literal load
                # — it sets the base address register for the computation.
                # Pattern: ADR Xn, label; LDRSW Xm, =imm; ...chain...; BR Xn
                pre_ea = lit_ea - 4
                if pre_ea >= func_start:
                    pw = _read_u32_le(pre_ea)
                    # ADR:  (pw & 0x9F000000) == 0x10000000
                    # ADRP: (pw & 0x9F000000) == 0x90000000
                    if (pw & 0x9F000000) in (0x10000000, 0x90000000):
                        _log("  dead-chain-nop: NOP ADR at 0x%X (was %s)" %
                             (pre_ea, _get_disasm(pre_ea)))
                        _nop_at(pre_ea)
                # NOP [lit_ea+4, ijmp_ea): the dead arithmetic after the
                # destroyed literal load, up to the patched direct branch.
                # Skip instructions that are standalone constant loads
                # (MOV Xn, #imm / MOVZ / MOVK) — these may be live values
                # needed by the code after the branch.
                scan_ea = lit_ea + 4  # lit_ea itself is already NOP'd
                while scan_ea < ijmp_ea:
                    w = _read_u32_le(scan_ea)
                    if w == 0xD503201F:
                        scan_ea += 4  # already NOP
                        continue
                    # Detect MOVZ / MOVK / MOV-wide-immediate — keep them
                    top = (w >> 24) & 0xFF
                    if top in (0xD2, 0x52, 0x72, 0xF2):
                        scan_ea += 4
                        continue
                    # Detect STR (pre/post-index or unsigned offset) — keep
                    # them too; they're benign stack writes that the
                    # decompiler handles without confusion.
                    if top in (0xB9, 0xB8, 0x29, 0xA9):
                        scan_ea += 4
                        continue
                    _log("  dead-chain-nop: NOP at 0x%X (was %s)" %
                         (scan_ea, _get_disasm(scan_ea)))
                    _nop_at(scan_ea)
                    scan_ea += 4

        # ---- Phase 2.5: pre-clean adjacent function junk bytes ----
        # We MUST do this HERE in the optimizer callback because
        # patch_byte is safe here but deadlocks in timer callbacks
        # (after auto_wait, patch_byte triggers IDA processor-module
        # notifications -> QReadWriteLock deadlock).
        adj_func_info = None
        _fe = _scan_for_func_end(target_addr)
        if _fe and _is_prologue_at(_fe):
            # Adjacent function has prologue at _fe.
            # Clean junk in a generous range first (safe: only patch_byte),
            # then scan for RET to find the end.
            _clean_junk_in_func_range(_fe, _fe + 0x400)
            _nfe = _scan_for_func_end(_fe)
            if _nfe:
                adj_func_info = (_fe, _nfe)
                _log("  auto-patch: adjacent func [0x%X-0x%X) detected, "
                     "junk pre-cleaned" % (_fe, _nfe))

        # ---- Phase 3: scan mba for func_end (arch-independent via m_ret) --
        mba_func_end = _find_func_end_from_mba(mba, target_addr)
        if mba_func_end:
            _log("  auto-patch: mba m_ret scan -> func_end = 0x%X" %
                 mba_func_end)

        # ---- Phase 4: schedule deferred fixup (runs after decompiler) ----
        _schedule_fixup(_DeferredFixup(
            ijmp_ea, target_addr, func_start,
            orig_ijmp_text, junk_insns, opaque_preds,
            adj_func_info, literal_load_patches,
            mba_func_end))
        _log("  auto-patch: deferred fixup queued (%d pending)" %
             len(_g_fixup_queue))

        self.total_resolved += 1
        return True

    def func(self, blk):
        self._func_calls += 1
        # Fast path: already timed out, skip everything (no time.time() call)
        if self._timed_out:
            return 0
        # Cooperative timeout
        if self._deadline and _time.time() > self._deadline:
            self._timed_out = True
            return 0
        try:
            return self._func_impl(blk)
        except Exception as e:
            _log("EXCEPTION in func(): %s" % str(e))
            traceback.print_exc()
            return 0

    def _func_impl(self, blk):
        # Run at MMAT_LOCOPT and above (skip very early maturity levels
        # where microcode is not yet cleaned up).
        if blk.mba.maturity < ida_hexrays.MMAT_LOCOPT:
            return 0

        tail = blk.tail
        if tail is None:
            return 0
        if tail.opcode != ida_hexrays.m_ijmp:
            return 0

        mba = blk.mba

        # --- Diagnostic ---
        _log("=" * 60)
        _log("FOUND ijmp in block %d (0x%X-0x%X), maturity=%d, func=0x%X" %
             (blk.serial, blk.start, blk.end, mba.maturity, mba.entry_ea))

        # Full block dump is expensive; only emit with VERBOSE
        if VERBOSE:
            _vlog("  total blocks: %d" % mba.qty)
            for i in range(mba.qty):
                b = mba.get_mblock(i)
                succs = []
                try:
                    for j in range(b.nsucc()):
                        succs.append(b.succ(j))
                except Exception:
                    pass
                _vlog("  blk[%d]: 0x%X-0x%X  type=%d  succs=%s" %
                      (i, b.start, b.end, b.type, succs))

        _log("  ijmp operands: l=%s  r=%s  d=%s" %
             (_mop_desc(tail.l), _mop_desc(tail.r), _mop_desc(tail.d)))

        # --- Step 1: constant propagation ----------------------------------
        st = _PropState()

        # Walk the predecessor chain backwards (multi-level) to build
        # propagation state.  We collect all unique predecessors in
        # reverse-topological order via iterative BFS, then propagate
        # through them from earliest to latest.
        MAX_PRED_DEPTH = 16
        ordered_preds = []    # list of block serial numbers, BFS order
        visited = {blk.serial}
        frontier = _get_preds(blk)
        depth = 0
        while frontier and depth < MAX_PRED_DEPTH:
            next_frontier = []
            for ps in frontier:
                if ps in visited:
                    continue
                visited.add(ps)
                ordered_preds.append(ps)
                pb = mba.get_mblock(ps)
                next_frontier.extend(_get_preds(pb))
            frontier = next_frontier
            depth += 1

        # Reverse so we propagate from the earliest block to the latest
        # (topological order for a linear chain).
        ordered_preds.reverse()

        _vlog("  predecessor chain (%d blocks, depth %d): %s" %
              (len(ordered_preds), depth, ordered_preds))

        dl = self._deadline
        for pred_serial in ordered_preds:
            if dl and _time.time() > dl:
                self._timed_out = True
                _log("  TIMEOUT before propagation (predecessor block %d)" % pred_serial)
                return 0
            pred_blk = mba.get_mblock(pred_serial)
            _vlog("  --- propagating predecessor block %d (0x%X-0x%X) ---" %
                  (pred_serial, pred_blk.start, pred_blk.end))
            if not _propagate(pred_blk, st, verbose=VERBOSE, deadline=dl):
                self._timed_out = True
                _log("  TIMEOUT during propagation (predecessor block %d)" % pred_serial)
                return 0

        # Propagate through the current block (up to the ijmp itself)
        _vlog("  --- propagating current block %d (0x%X-0x%X) ---" %
              (blk.serial, blk.start, blk.end))
        if not _propagate(blk, st, stop_at=tail, verbose=VERBOSE, deadline=dl):
            self._timed_out = True
            _log("  TIMEOUT during propagation (current block %d)" % blk.serial)
            return 0

        _log("  propagation state: %s" % st.dump())

        # --- Step 2: resolve the ijmp target address -----------------------
        # Try both tail.d and tail.r -- the computed address location
        # depends on IDA version and ijmp encoding.
        target_addr = _eval_op(tail.d, st)
        target_src = "d"
        if target_addr is None:
            target_addr = _eval_op(tail.r, st)
            target_src = "r"
        if target_addr is None:
            target_addr = _eval_op(tail.l, st)
            target_src = "l"

        if target_addr is None:
            _log("  could not resolve ijmp target -- skipping")
            return 0

        target_addr = target_addr & 0xFFFFFFFFFFFFFFFF
        _log("  resolved target: 0x%X (from operand %s)" %
             (target_addr, target_src))

        # --- Step 3: find the microcode block that starts at target --------
        target_blk_serial = -1
        for i in range(mba.qty):
            b = mba.get_mblock(i)
            if b.start == target_addr:
                target_blk_serial = i
                break

        if target_blk_serial < 0:
            _log("  NO block starts at 0x%X -- target outside function" % target_addr)
            # --- Auto-patch: replace indirect JMP with direct JMP at binary level,
            #     then fix the function boundary so the next decompilation succeeds.
            patched = self._auto_patch_ijmp(mba, blk, tail, target_addr)
            if patched:
                _log("  AUTO-PATCHED binary at 0x%X -> 0x%X" % (tail.ea, target_addr))
                _log("  Please re-decompile this function to see the result.")
            return 0

        # --- Sanity checks ---
        # Don't redirect to self
        if target_blk_serial == blk.serial:
            _log("  target is same block -- skipping (self-loop)")
            return 0

        # Don't redirect to the special entry block (block 0) or exit block
        # (last block) -- these are synthetic.
        if target_blk_serial == 0:
            _log("  target is block 0 (entry block) -- skipping")
            return 0
        if target_blk_serial == mba.qty - 1:
            _log("  target is last block (exit block) -- skipping")
            return 0

        # Verify the target block has actual code
        target_blk = mba.get_mblock(target_blk_serial)
        if target_blk.head is None:
            _log("  target block %d is empty -- skipping" % target_blk_serial)
            return 0

        _log("  -> REWRITING to goto block %d (0x%X)" %
             (target_blk_serial, target_addr))

        # --- Step 4: rewrite  ijmp -> goto ---------------------------------
        # Save old successor info before rewriting
        old_succs = []
        try:
            for j in range(blk.nsucc()):
                old_succs.append(blk.succ(j))
        except (AttributeError, TypeError):
            try:
                for s in blk.succset:
                    old_succs.append(s)
            except Exception:
                pass

        _log("  old successors: %s" % old_succs)

        tail.opcode = ida_hexrays.m_goto

        # Set l = block reference (mop_b)
        tail.l.erase()
        tail.l.t = ida_hexrays.mop_b
        tail.l.b = target_blk_serial
        tail.l.size = 0

        # Clear unused operands
        tail.r.erase()
        tail.d.erase()

        # --- Step 5: fix control flow graph (successor/predecessor lists) ---
        # Update succset: replace all old successors with the new target
        try:
            blk.succset.flush()
            blk.succset.add(target_blk_serial)
        except Exception as e:
            _log("  WARNING: succset.flush/add failed: %s" % e)
            try:
                # Clear all existing successors, then add the new one
                while len(blk.succset) > 0:
                    blk.succset.pop()
                blk.succset.add(target_blk_serial)
            except Exception as e2:
                _log("  WARNING: succset fallback failed: %s" % e2)

        # Add ourselves to the target block's predecessor set
        try:
            mba.get_mblock(target_blk_serial).predset.add(blk.serial)
        except Exception as e:
            _log("  WARNING: predset.add failed: %s" % e)

        # Remove ourselves from old successors' predecessor sets
        for old_s in old_succs:
            if old_s != target_blk_serial:
                try:
                    mba.get_mblock(old_s).predset._del(blk.serial)
                except Exception as e:
                    _log("  WARNING: predset._del(%d) failed: %s" % (old_s, e))

        # Since we changed the control flow graph, invalidate use/def chains
        mba.mark_chains_dirty()

        # Verify microcode after modification (non-fatal: log but continue)
        try:
            mba.verify(True)
            _log("  verify OK")
        except Exception as e:
            _log("  WARNING: verify failed (non-fatal): %s" % str(e))
            # Continue anyway -- the decompiler may still produce output

        self.total_resolved += 1
        _log("  RESOLVED (%d total)" % self.total_resolved)
        return 1   # 1 change made -- Hex-Rays will re-run optimization


# ---------------------------------------------------------------------------
# Install / uninstall helpers
# ---------------------------------------------------------------------------

_g_optimizer = None   # prevent GC
_g_timeout_funcs = set()  # EAs that timed out — skip in subsequent passes


def cb_deobf_install():
    """Install the microcode optimizer.  Call once; it persists for the
    entire IDA session (across all decompilations).

    Uses a cross-namespace marker on ida_hexrays to prevent the plugin
    and Script File from registering two competing optimizers.
    """
    global _g_optimizer, _ARCH

    # Check cross-namespace marker (plugin vs script-file share this)
    existing = getattr(ida_hexrays, '_cb_deobf_optimizer', None)
    if existing is not None:
        _g_optimizer = existing
        _log("reusing existing optimizer (%d resolved so far)"
             % _g_optimizer.total_resolved)
        return True

    if _g_optimizer is not None:
        _log("already installed (%d resolved so far)"
             % _g_optimizer.total_resolved)
        return True

    if not ida_hexrays.init_hexrays_plugin():
        print("[cb_deobf_mc] ERROR: Hex-Rays decompiler not available")
        return False

    _ARCH = _detect_arch()
    print("[cb_deobf_mc] Detected architecture: %s" % _ARCH)

    _g_optimizer = CBDeobfOptimizer()
    _g_optimizer.install()
    ida_hexrays._cb_deobf_optimizer = _g_optimizer  # cross-namespace marker
    _register_menus()
    _update_toggle_label()
    print("[cb_deobf_mc] Optimizer ENABLED.  Use F5 to fix single functions, "
          "or Edit > CB Deobf > Fix All Functions for batch mode.")
    return True


def cb_deobf_uninstall():
    """Remove the optimizer."""
    global _g_optimizer

    if _g_optimizer is None:
        print("[cb_deobf_mc] not installed")
        return

    _g_optimizer.remove()
    print("[cb_deobf_mc] Optimizer DISABLED (%d total resolved)" %
          _g_optimizer.total_resolved)
    _g_optimizer = None
    # Clear cross-namespace marker
    if getattr(ida_hexrays, '_cb_deobf_optimizer', None) is not None:
        del ida_hexrays._cb_deobf_optimizer
    _update_toggle_label()


def _update_toggle_label():
    """Refresh the Toggle menu label to reflect current optimizer state."""
    state = "ON" if cb_deobf_is_installed() else "OFF"
    ida_kernwin.update_action_label(_ACT_TOGGLE, "Optimizer [%s]" % state)


def cb_deobf_is_installed():
    """Return True if the optimizer is currently active."""
    return _g_optimizer is not None


# ---------------------------------------------------------------------------
# Batch operations
# ---------------------------------------------------------------------------

# NOTE: Do NOT use register_timer() to call decompile(). It deadlocks:
#   activateTimers → _tick → decompile → optimizer → patch_byte
#   → IDP notify → kernwin → contendedTryLockForWrite → STUCK
# (Evidence: sample trace 20260227_210619, lines 46-99, 8306/8306 samples.)

_g_fix_all_running = False


def _decompile_with_timeout(ea, timeout=None, mark_dirty=True, flags=0):
    """Plugin wrapper around :func:`decompile_with_timeout`.

    Adds cooperative deadline (``_g_optimizer._deadline``) so the
    optimizer callback can short-circuit early without waiting for
    the hard watchdog cancel.
    """
    if timeout is None:
        timeout = _g_optimizer.DECOMPILE_TIMEOUT if _g_optimizer else 0

    # Cooperative timeout for the optimizer callback (fast path)
    if _g_optimizer is not None:
        _g_optimizer._timed_out = False
        _g_optimizer._func_calls = 0
        _g_optimizer._deadline = (_time.time() + timeout) if timeout > 0 else 0

    try:
        return decompile_with_timeout(ea, timeout=timeout,
                                      mark_dirty=mark_dirty, flags=flags)
    finally:
        if _g_optimizer is not None:
            _g_optimizer._deadline = 0


def cb_deobf_fix_all():
    """Decompile ALL functions in the IDB to trigger the optimizer.

    Synchronous loop with show_wait_box / replace_wait_box for progress.
    Automatically installs the optimizer if not already active.
    """
    global _g_fix_all_running
    if _g_fix_all_running:
        print("[cb_deobf_mc] Fix-all already in progress")
        return

    if not cb_deobf_is_installed():
        if not cb_deobf_install():
            return

    nfuncs = ida_funcs.get_func_qty()
    if nfuncs == 0:
        print("[cb_deobf_mc] No functions found in IDB")
        return

    resolved_before = _g_optimizer.total_resolved
    failed = 0
    skipped = 0
    _g_timeout_funcs.clear()

    _g_fix_all_running = True
    _log("fix-all: batch decompiling %d functions" % nfuncs)
    ida_kernwin.show_wait_box("CB Deobf: scanning %d functions..." % nfuncs)
    try:
        for i in range(nfuncs):
            try:
                if ida_kernwin.user_cancelled():
                    _log("fix-all: cancelled by user at %d/%d" % (i, nfuncs))
                    break
            except AttributeError:
                pass

            func = ida_funcs.getn_func(i)
            if func is None:
                continue

            ea = func.start_ea

            # Skip large jump tables before decompiling — these have
            # huge switch tables that cause the CLP solver to run for
            # 17-20s before set_cancelled() takes effect.
            if _has_large_jump_table(ea, func.end_ea):
                skipped += 1
                _g_timeout_funcs.add(ea)
                _log("fix-all: func %d/%d 0x%X is large jump table, skipped"
                     % (i, nfuncs, ea))
                continue

            t0 = _time.time()
            cfunc, timed_out = _decompile_with_timeout(ea)
            if cfunc is None and not timed_out:
                failed += 1
            elapsed = _time.time() - t0
            calls = _g_optimizer._func_calls if _g_optimizer else 0

            if timed_out or (_g_optimizer and _g_optimizer._timed_out):
                skipped += 1
                _g_timeout_funcs.add(ea)
                _log("fix-all: func %d/%d 0x%X TIMEOUT after %.1fs (%d callbacks, skipped)"
                     % (i, nfuncs, ea, elapsed, calls))
            elif elapsed >= 1.0:
                _log("fix-all: func %d/%d 0x%X took %.1fs" % (i, nfuncs, ea, elapsed))

            if i % 10 == 0:
                new_res = _g_optimizer.total_resolved - resolved_before
                ida_kernwin.replace_wait_box(
                    "CB Deobf: %d / %d functions\n"
                    "Resolved: %d  |  Failed: %d  |  Timeout: %d"
                    % (i, nfuncs, new_res, failed, skipped))

        # ---- Multi-pass convergence: flush deferred fixups and
        #      re-decompile functions whose boundaries were extended.
        #      Newly-included code may contain additional computed
        #      branches that weren't in the original function boundary.
        MAX_CONV_PASSES = 5
        for _pass in range(1, MAX_CONV_PASSES + 1):
            if not _g_fixup_queue:
                break

            n_pending = len(_g_fixup_queue)
            _log("fix-all: convergence pass %d (%d pending fixups)" %
                 (_pass, n_pending))
            ida_kernwin.replace_wait_box(
                "CB Deobf: convergence pass %d (%d fixups)..." %
                (_pass, n_pending))

            # Drain fixup queue (timer hasn't fired — main thread is busy)
            extended_funcs = set()
            batch = list(_g_fixup_queue)
            _g_fixup_queue.clear()
            for fix in batch:
                extended_funcs.add(fix.func_start)
                try:
                    _apply_single_fixup(fix)
                except Exception as e:
                    _log("  convergence fixup FAILED (0x%X): %s" %
                         (fix.ijmp_ea, str(e)))

            # NOTE: auto_wait() removed — all IDB-modifying ops (add_func,
            # del_func) are synchronous.  Decompiler reads bytes directly.
            # Pending auto-analysis drains after script returns to event loop.
            # _repair_swallowed_prologues also skipped — it only fixes issues
            # caused by auto_wait extending boundaries beyond what we set.
            n_rep = 0
            if False:  # was: _repair_swallowed_prologues(extended_funcs)
                _log("fix-all: convergence pass %d: repaired %d "
                     "boundary conflict(s)" % (_pass, n_rep))

            # Re-decompile the extended functions
            for ea in sorted(extended_funcs):
                try:
                    if ida_kernwin.user_cancelled():
                        break
                except AttributeError:
                    pass
                if ea in _g_timeout_funcs:
                    continue
                func = ida_funcs.get_func(ea)
                if func is None:
                    continue
                cfunc, _to = _decompile_with_timeout(ea)
                if _to or (_g_optimizer and _g_optimizer._timed_out):
                    _g_timeout_funcs.add(ea)

            _log("fix-all: convergence pass %d done" % _pass)

        # Flush any remaining fixups from the final convergence pass
        if _g_fixup_queue:
            batch = list(_g_fixup_queue)
            _g_fixup_queue.clear()
            for fix in batch:
                try:
                    _apply_single_fixup(fix)
                except Exception as e:
                    _log("  final fixup FAILED (0x%X): %s" %
                         (fix.ijmp_ea, str(e)))

        # ---- Residual fix: extend tiny-prologue functions ----------------
        # On x86_64, some functions have boundaries that only cover the
        # prologue.  The indirect jump is outside the boundary, invisible
        # to the optimizer.  Extend these and re-run a mini fix_all loop.
        MAX_RESIDUAL_PASSES = 3
        for _rpass in range(1, MAX_RESIDUAL_PASSES + 1):
            try:
                if ida_kernwin.user_cancelled():
                    break
            except AttributeError:
                pass

            ida_kernwin.replace_wait_box(
                "CB Deobf: residual fix pass %d..." % _rpass)

            n_ext, ext_eas = _extend_tiny_prologue_funcs()
            if n_ext == 0:
                break

            _log("fix-all: residual pass %d: extended %d tiny-prologue "
                 "function(s)" % (_rpass, n_ext))
            # auto_wait() removed

            # Re-decompile only the extended functions (not ALL).
            for ea in sorted(ext_eas):
                try:
                    if ida_kernwin.user_cancelled():
                        break
                except AttributeError:
                    pass
                if ea in _g_timeout_funcs:
                    continue
                cfunc, _to = _decompile_with_timeout(ea)
                if _to or (_g_optimizer and _g_optimizer._timed_out):
                    _g_timeout_funcs.add(ea)

            # Drain any new fixups
            if _g_fixup_queue:
                n_fix = len(_g_fixup_queue)
                batch2 = list(_g_fixup_queue)
                _g_fixup_queue.clear()
                for fix in batch2:
                    try:
                        _apply_single_fixup(fix)
                    except Exception:
                        pass
                # auto_wait() removed
                _log("fix-all: residual pass %d: %d fixup(s) applied" %
                     (_rpass, n_fix))

            _log("fix-all: residual pass %d done" % _rpass)

        # ---- Phase 4: standalone opaque predicate cleaning ----
        # Opaque predicates that don't guard computed branches may still
        # produce JUMPOUT.  Scan all functions for complementary Jcc pairs,
        # NOP the junk bytes, and rebuild IDB items.
        MAX_OPAQUE_PASSES = 3
        for _opass in range(1, MAX_OPAQUE_PASSES + 1):
            try:
                if ida_kernwin.user_cancelled():
                    break
            except AttributeError:
                pass

            ida_kernwin.replace_wait_box(
                "CB Deobf: Phase 4 — opaque predicate cleanup (pass %d)..."
                % _opass)

            op_affected, op_count = _clean_standalone_opaque_preds()
            if not op_affected:
                break

            _log("fix-all: Phase 4 pass %d: cleaned %d opaque pred(s) "
                 "in %d function(s)" % (_opass, op_count, len(op_affected)))
            # NOTE: auto_wait() removed — decompiler reads bytes directly and
            # does not need IDA auto-analysis to complete.  Tested: all
            # affected functions decompile correctly without auto_wait().
            # The previous auto_wait() here blocked for 7+ minutes on x86_64
            # binaries due to cascading re-analysis from 25+ function rebuilds.

            # Re-decompile affected functions — newly-visible code may
            # contain computed branches the optimizer can now resolve.
            for ea in sorted(op_affected):
                try:
                    if ida_kernwin.user_cancelled():
                        break
                except AttributeError:
                    pass
                if ea in _g_timeout_funcs:
                    continue
                func = ida_funcs.get_func(ea)
                if func is None:
                    continue
                cfunc, _to = _decompile_with_timeout(ea)
                if _to or (_g_optimizer and _g_optimizer._timed_out):
                    _g_timeout_funcs.add(ea)

            # Drain any new fixups from the optimizer
            if _g_fixup_queue:
                n_fix = len(_g_fixup_queue)
                batch_op = list(_g_fixup_queue)
                _g_fixup_queue.clear()
                for fix in batch_op:
                    try:
                        _apply_single_fixup(fix)
                    except Exception:
                        pass
                # auto_wait() removed — decompiler doesn't need it
                _log("fix-all: Phase 4 pass %d: %d new fixup(s) applied"
                     % (_opass, n_fix))

            _log("fix-all: Phase 4 pass %d done" % _opass)

        # ---- Phase 5: boundary repair for remaining JUMPOUTs ----
        MAX_BOUNDARY_PASSES = 3
        for _bpass in range(1, MAX_BOUNDARY_PASSES + 1):
            try:
                if ida_kernwin.user_cancelled():
                    break
            except AttributeError:
                pass
            ida_kernwin.replace_wait_box(
                "CB Deobf: Phase 5 — boundary repair (pass %d)..."
                % _bpass)
            br_set, br_count = _repair_jumpout_boundaries()
            if not br_set:
                break
            _log("fix-all: Phase 5 pass %d: repaired %d boundary(ies)"
                 % (_bpass, br_count))
            # NOTE: auto_wait() removed — same as Phase 4, decompiler
            # reads bytes directly. Pending analysis drains asynchronously.
            # Re-decompile repaired functions
            for ea in sorted(br_set):
                if ea in _g_timeout_funcs:
                    continue
                cfunc, _to = _decompile_with_timeout(ea)
                if _to or (_g_optimizer and _g_optimizer._timed_out):
                    _g_timeout_funcs.add(ea)
            # Drain any new fixups from optimizer
            if _g_fixup_queue:
                n_fix = len(_g_fixup_queue)
                batch2 = list(_g_fixup_queue)
                _g_fixup_queue.clear()
                for fix in batch2:
                    try:
                        _apply_single_fixup(fix)
                    except Exception:
                        pass
                # auto_wait() removed — same reason as above
                _log("fix-all: Phase 5 pass %d: %d fixup(s) applied"
                     % (_bpass, n_fix))
            _log("fix-all: Phase 5 pass %d done" % _bpass)

    finally:
        ida_kernwin.hide_wait_box()
        _g_fix_all_running = False

    new_resolved = _g_optimizer.total_resolved - resolved_before
    if _g_timeout_funcs:
        _log("fix-all: %d function(s) in timeout skip-list: %s"
             % (len(_g_timeout_funcs),
                ", ".join("0x%X" % a for a in sorted(_g_timeout_funcs))))
    msg = ("Fix-all complete: %d functions scanned, "
           "%d resolved, %d failed, %d timeout" % (nfuncs, new_resolved, failed, skipped))
    _log(msg)
    print("[cb_deobf_mc] " + msg)
    ida_kernwin.info(msg)


def cb_deobf_fix_current():
    """Decompile the function at the current cursor position.

    Automatically installs the optimizer if not already active.
    """
    if not cb_deobf_is_installed():
        if not cb_deobf_install():
            return

    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func is None:
        ida_kernwin.warning("[cb_deobf_mc] No function at 0x%X" % ea)
        return

    resolved_before = _g_optimizer.total_resolved
    _log("fix-current: decompiling 0x%X" % func.start_ea)
    try:
        ida_hexrays.decompile(func.start_ea)
        new_res = _g_optimizer.total_resolved - resolved_before
        if new_res:
            print("[cb_deobf_mc] 0x%X: %d indirect jump(s) resolved" %
                  (func.start_ea, new_res))
        else:
            print("[cb_deobf_mc] 0x%X: no new resolutions (clean)" %
                  func.start_ea)
    except Exception as e:
        ida_kernwin.warning("Decompilation failed at 0x%X:\n%s" %
                            (func.start_ea, str(e)))


# ---------------------------------------------------------------------------
# IDA Action handlers & context menus
# ---------------------------------------------------------------------------

_ACT_TOGGLE      = "cb_deobf:toggle"
_ACT_FIX_ALL     = "cb_deobf:fix_all"
_ACT_FIX_CURRENT = "cb_deobf:fix_current"
_ACT_ABOUT       = "cb_deobf:about"


class _ToggleHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if cb_deobf_is_installed():
            cb_deobf_uninstall()
        else:
            cb_deobf_install()
        return 1

    def update(self, ctx):
        _update_toggle_label()
        return ida_kernwin.AST_ENABLE_ALWAYS


class _FixAllHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        cb_deobf_fix_all()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class _FixCurrentHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        cb_deobf_fix_current()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class _AboutHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ida_kernwin.info(
            "TITLE %s\n"
            "ICON INFO\n"
            "AUTOHIDE NONE\n"
            "HIDECANCEL\n"
            "\n"
            "%s v%s\n\n"
            "Hex-Rays microcode plugin that resolves computed\n"
            "indirect jumps (BR Xn / JMP reg) via constant\n"
            "propagation. Supports ARM64 and x86_64.\n\n"
            "Usage:\n"
            "  - F5 on any function to auto-deobfuscate\n"
            "  - Right-click > CB Deobf > Fix All Functions\n"
            "  - Hotkey: %s" % (PLUGIN_NAME, PLUGIN_NAME, PLUGIN_VERSION, PLUGIN_HOTKEY))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class _DeobfUIHooks(ida_kernwin.UI_Hooks):
    """Add 'CB Deobf' submenu to IDA View (disassembly) context menu."""

    def finish_populating_widget_popup(self, widget, popup):
        wtype = ida_kernwin.get_widget_type(widget)
        if wtype == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(
                widget, popup, _ACT_FIX_CURRENT, "CB Deobf/")
            ida_kernwin.attach_action_to_popup(
                widget, popup, _ACT_FIX_ALL, "CB Deobf/")
            ida_kernwin.attach_action_to_popup(
                widget, popup, _ACT_TOGGLE, "CB Deobf/")
            ida_kernwin.attach_action_to_popup(
                widget, popup, "", "CB Deobf/")
            ida_kernwin.attach_action_to_popup(
                widget, popup, _ACT_ABOUT, "CB Deobf/")


class _DeobfHxeHooks(ida_hexrays.Hexrays_Hooks):
    """Add 'CB Deobf' submenu to Pseudocode view context menu."""

    def populating_popup(self, widget, popup, vu):
        ida_kernwin.attach_action_to_popup(
            widget, popup, _ACT_FIX_CURRENT, "CB Deobf/")
        ida_kernwin.attach_action_to_popup(
            widget, popup, _ACT_FIX_ALL, "CB Deobf/")
        ida_kernwin.attach_action_to_popup(
            widget, popup, _ACT_TOGGLE, "CB Deobf/")
        ida_kernwin.attach_action_to_popup(
            widget, popup, "", "CB Deobf/")
        ida_kernwin.attach_action_to_popup(
            widget, popup, _ACT_ABOUT, "CB Deobf/")
        return 0


_g_ui_hooks = None
_g_hxe_hooks = None
_g_menus_registered = False


def _register_menus():
    """Register action handlers, main-menu items, and context-menu hooks.

    Safe to call multiple times (idempotent).
    """
    global _g_ui_hooks, _g_hxe_hooks, _g_menus_registered

    if _g_menus_registered:
        return

    _action_defs = [
        (_ACT_FIX_CURRENT, "Fix Current Function",  _FixCurrentHandler()),
        (_ACT_FIX_ALL,     "Fix All Functions",      _FixAllHandler()),
        (_ACT_TOGGLE,      "Optimizer",              _ToggleHandler()),
        (_ACT_ABOUT,       "About",                  _AboutHandler()),
    ]

    for act_id, label, handler in _action_defs:
        desc = ida_kernwin.action_desc_t(act_id, label, handler, "", "", -1)
        ida_kernwin.register_action(desc)
        ida_kernwin.attach_action_to_menu(
            "Edit/CB Deobf/", act_id, ida_kernwin.SETMENU_APP)

    # Context menu hooks — IDA View
    _g_ui_hooks = _DeobfUIHooks()
    _g_ui_hooks.hook()

    # Context menu hooks — Pseudocode view
    if ida_hexrays.init_hexrays_plugin():
        _g_hxe_hooks = _DeobfHxeHooks()
        _g_hxe_hooks.hook()

    _g_menus_registered = True
    _log("menus & context-menu hooks registered")


def _unregister_menus():
    """Remove all action handlers and hooks."""
    global _g_ui_hooks, _g_hxe_hooks, _g_menus_registered

    if not _g_menus_registered:
        return

    if _g_hxe_hooks:
        _g_hxe_hooks.unhook()
        _g_hxe_hooks = None

    if _g_ui_hooks:
        _g_ui_hooks.unhook()
        _g_ui_hooks = None

    for act_id in (_ACT_FIX_CURRENT, _ACT_FIX_ALL, _ACT_TOGGLE, _ACT_ABOUT):
        ida_kernwin.unregister_action(act_id)

    _g_menus_registered = False
    _log("menus & context-menu hooks unregistered")


# ---------------------------------------------------------------------------
# IDA Plugin class (Edit -> Plugins -> CB Deobf)
# ---------------------------------------------------------------------------

PLUGIN_NAME    = "Computed-Branch Deobfuscator"
PLUGIN_VERSION = "0.0.1"
PLUGIN_HOTKEY  = "Ctrl-Shift-A"
PLUGIN_COMMENT = "Toggle computed-branch deobfuscator (Hex-Rays microcode)"
PLUGIN_HELP    = ""


class CBDeobfPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP      # keep loaded across IDB switches
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP

    def init(self):
        """Called once when IDA loads the plugin.

        Always registers menus and prints the banner regardless of
        whether Hex-Rays is available yet — the decompiler availability
        is checked at actual use time (run / menu callbacks).
        """
        _register_menus()
        print("-" * 79)
        print("[cb_deobf] %s v%s loaded.  Hotkey: %s" %
              (PLUGIN_NAME, PLUGIN_VERSION, PLUGIN_HOTKEY))
        print("-" * 79)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Called when the user activates the plugin (hotkey / menu).
        Toggles the optimizer on/off."""
        if cb_deobf_is_installed():
            cb_deobf_uninstall()
        else:
            cb_deobf_install()

    def term(self):
        """Called when IDA is shutting down or the plugin is unloaded."""
        cb_deobf_uninstall()
        _unregister_menus()


def PLUGIN_ENTRY():
    """Standard IDA plugin entry point."""
    return CBDeobfPlugin()


# ---------------------------------------------------------------------------
# Script-mode entry point (File -> Script File)
# ---------------------------------------------------------------------------
# _SCRIPT_MODE is set at the top of the file when __name__ == "__main__"
# and ida_hexrays is available (i.e. running inside IDA as a script).

if _SCRIPT_MODE:
    cb_deobf_install()
    cb_deobf_fix_all()
