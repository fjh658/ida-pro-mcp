"""Debugger operations for IDA Pro MCP.

This module provides comprehensive debugging functionality including:
- Debugger control (start, exit, continue, step, run_to)
- Breakpoint management (add, delete, enable/disable, list)
- Register inspection (all registers, GP registers, specific registers)
- Memory operations (read/write debugger memory)
- Call stack inspection
"""

import os
import queue
import threading
from typing import Annotated

import ida_dbg
import ida_entry
import ida_ida
import ida_idd
import ida_idaapi
import ida_name
import idaapi

from .rpc import tool, unsafe, ext
from .sync import idasync, sync_wrapper, IDAError
from .utils import (
    RegisterValue,
    ThreadRegisters,
    Breakpoint,
    BreakpointOp,
    MemoryRead,
    MemoryPatch,
    normalize_list_input,
    normalize_dict_list,
    parse_address,
)


# ============================================================================
# Constants and Helper Functions
# ============================================================================

_DBG_START_TIMEOUT = 10.0
_DBG_EXIT_TIMEOUT = 10.0
_DBG_ACTION_TIMEOUT = 5.0

_GP_REGS_X86 = {
    "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP",
    "EFLAGS",
}

_GP_REGS_X64 = {
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "RFLAGS",
}

_GP_REGS_ARM64 = {
    "X0",  "X1",  "X2",  "X3",  "X4",  "X5",  "X6",  "X7",
    "X8",  "X9",  "X10", "X11", "X12", "X13", "X14", "X15",
    "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23",
    "X24", "X25", "X26", "X27", "X28",
    "X29", "X30",  # FP, LR
    "SP", "PC", "PSR",
}

_GP_REGS_ARM32 = {
    "R0",  "R1",  "R2",  "R3",  "R4",  "R5",  "R6",  "R7",
    "R8",  "R9",  "R10", "R11", "R12",
    "SP", "LR", "PC", "CPSR",
}


_gp_regs_cache: set[str] | None = None


def _get_gp_register_names() -> set[str]:
    """Return GP register names for the current processor (cached)."""
    global _gp_regs_cache
    if _gp_regs_cache is not None:
        return _gp_regs_cache
    procname = ida_ida.inf_get_procname().upper()
    if procname in ("ARM", "ARMB"):
        bitness = 64 if ida_ida.inf_is_64bit() else 32
        result = _GP_REGS_ARM64 if bitness == 64 else _GP_REGS_ARM32
    elif ida_ida.inf_is_64bit():
        result = _GP_REGS_X64
    else:
        result = _GP_REGS_X86
    _gp_regs_cache = result
    return result


def dbg_ensure_running() -> "ida_idd.debugger_t":
    dbg = ida_idd.get_dbg()
    if not dbg:
        raise IDAError("Debugger not running")
    if not ida_dbg.is_debugger_on():
        raise IDAError("Debugger not running")
    return dbg


def _get_registers_for_thread(dbg: "ida_idd.debugger_t", tid: int) -> ThreadRegisters:
    """Helper to get registers for a specific thread."""
    regs = []
    regvals: ida_idd.regvals_t = ida_dbg.get_reg_vals(tid)
    for reg_index, rv in enumerate(regvals):
        rv: ida_idd.regval_t
        reg_info = dbg.regs(reg_index)

        try:
            reg_value = rv.pyval(reg_info.dtype)
        except ValueError:
            reg_value = ida_idaapi.BADADDR

        if isinstance(reg_value, int):
            reg_value = hex(reg_value)
        elif isinstance(reg_value, bytes):
            reg_value = reg_value.hex(" ")
        else:
            reg_value = str(reg_value)
        regs.append(
            RegisterValue(
                name=reg_info.name,
                value=reg_value,
            )
        )
    return ThreadRegisters(
        thread_id=tid,
        registers=regs,
    )


def _get_registers_general_for_thread(
    dbg: "ida_idd.debugger_t", tid: int
) -> ThreadRegisters:
    """Helper to get general-purpose registers for a specific thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    general_registers = [
        reg
        for reg in all_registers["registers"]
        if reg["name"] in _get_gp_register_names()
    ]
    return ThreadRegisters(
        thread_id=tid,
        registers=general_registers,
    )


def _get_registers_specific_for_thread(
    dbg: "ida_idd.debugger_t", tid: int, register_names: list[str]
) -> ThreadRegisters:
    """Helper to get specific registers for a given thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    names_upper = {n.upper() for n in register_names}
    specific_registers = [
        reg for reg in all_registers["registers"] if reg["name"].upper() in names_upper
    ]
    return ThreadRegisters(
        thread_id=tid,
        registers=specific_registers,
    )


def list_breakpoints():
    breakpoints: list[Breakpoint] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            breakpoints.append(
                Breakpoint(
                    addr=hex(bpt.ea),
                    enabled=bool(bpt.flags & ida_dbg.BPT_ENABLED),
                    condition=str(bpt.condition) if bpt.condition else None,
                )
            )
    return breakpoints


# ============================================================================
# Debugger Control Operations
# ============================================================================


_dbg_start_lock = threading.Lock()


@ext("dbg")
@unsafe
@tool
def dbg_start():
    """Start debugger"""
    if not _dbg_start_lock.acquire(blocking=False):
        raise IDAError(
            "Debugger start already in progress. "
            "Please handle any pending dialogs in IDA."
        )
    try:
        return _dbg_start_impl()
    finally:
        _dbg_start_lock.release()


def _dbg_start_impl():
    suspend_event = threading.Event()

    # Phase 1a: check state, set breakpoints, install hook
    def _setup():
        # Debugger must be loaded by user (Debugger > Select debugger)
        if ida_idd.get_dbg() is None:
            raise IDAError(
                "No debugger loaded. "
                "Please select a debugger via Debugger > Select debugger."
            )

        if len(list_breakpoints()) == 0:
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                addr = ida_entry.get_entry(ordinal)
                if addr != ida_idaapi.BADADDR:
                    ida_dbg.add_bpt(addr, 0, idaapi.BPT_SOFT)

        # Already running? Return structured info directly.
        if ida_dbg.is_debugger_on():
            dbg = ida_idd.get_dbg()
            ip = ida_dbg.get_ip_val()
            result = {"status": "already_running"}
            if ip is not None:
                result["ip"] = hex(ip)
            if dbg:
                result["debugger"] = dbg.name
                result["is_remote"] = dbg.is_remote()
            return result

        class _WaitHook(ida_dbg.DBG_Hooks):
            def __init__(self):
                super().__init__()
                self.info = {}

            def dbg_process_start(self, pid, tid, ea,
                                  modinfo_name, modinfo_base, modinfo_size):
                self.info["pid"] = pid
                self.info["tid"] = tid
                self.info["main_module"] = modinfo_name
                self.info["module_base"] = hex(modinfo_base)
                dbg = ida_idd.get_dbg()
                if dbg:
                    self.info["debugger"] = dbg.name
                    self.info["is_remote"] = dbg.is_remote()

            def _finish(self):
                """Auto-unhook on terminal event."""
                try:
                    self.unhook()
                except Exception:
                    pass

            def dbg_suspend_process(self):
                self.info["status"] = "suspended"
                self._finish()
                suspend_event.set()

            def dbg_process_exit(self, pid, tid, ea, exit_code):
                self.info["status"] = "exited"
                self.info["exit_code"] = exit_code
                self._finish()
                suspend_event.set()

            def dbg_exception(self, pid, tid, ea, exc_code,
                              exc_can_cont, exc_ea, exc_info):
                self.info["exception_addr"] = hex(exc_ea)
                self.info["exception_code"] = exc_code
                self.info["exception_info"] = exc_info
                return 0  # use default handler

        hook = _WaitHook()
        hook.hook()
        suspend_event._dbg_hook = hook  # prevent GC
        return None  # proceed to start_process

    _setup.__name__ = "dbg_start_setup"
    result = sync_wrapper(_setup, timeout_override=5.0)
    if isinstance(result, dict):
        return result

    # Phase 1b: start_process in a background thread — execute_sync
    # blocks the calling thread until the main thread runs the callback.
    # If a modal dialog blocks the main thread, execute_sync never returns.
    # We run it in a daemon thread and wait on suspend_event instead.
    start_q = queue.Queue()

    def _do_start_thread():
        def _do_start():
            try:
                idaapi.start_process("", "", "")
                start_q.put(None)
            except Exception as e:
                start_q.put(e)
        idaapi.execute_sync(_do_start, idaapi.MFF_WRITE)

    t = threading.Thread(target=_do_start_thread, daemon=True)
    t.start()

    # Phase 2: wait for process to suspend.
    # This covers both normal startup AND dialog-blocked scenarios —
    # user handles dialogs, process eventually starts, hook fires.
    # Hook auto-unhooks in _finish().
    if not suspend_event.wait(timeout=_DBG_START_TIMEOUT):
        # Differentiate: is start_process still blocked by a dialog,
        # or did it return but the process didn't suspend?
        if start_q.empty():
            raise IDAError(
                "Debugger start blocked by a dialog in IDA "
                "(e.g. debug application setup, database patched warning, "
                "or security confirmation). "
                "Please handle it and try again."
            )
        raise IDAError(
            "Debugger start timed out waiting for process to suspend. "
            "Check IDA for any pending dialogs."
        )

    # Phase 3: read IP (hook already unhooked itself), return structured info
    def _phase3():
        hook = getattr(suspend_event, '_dbg_hook', None)
        info = hook.info if hook else {}

        result = dict(info)  # copy hook-collected info
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            result["ip"] = hex(ip)
        if "status" not in result:
            if ida_dbg.is_debugger_on():
                result["status"] = "suspended"
            else:
                result["status"] = "exited"
        return result

    _phase3.__name__ = "dbg_start_phase3"
    return sync_wrapper(_phase3, timeout_override=5.0)


_dbg_exit_lock = threading.Lock()


@ext("dbg")
@unsafe
@tool
def dbg_exit():
    """Exit debugger"""
    if not _dbg_exit_lock.acquire(blocking=False):
        raise IDAError(
            "Debugger exit already in progress. "
            "Please handle any pending dialogs in IDA."
        )
    try:
        return _dbg_exit_impl()
    finally:
        _dbg_exit_lock.release()


def _dbg_exit_impl():
    exit_event = threading.Event()

    def _setup():
        dbg_ensure_running()

        class _ExitHook(ida_dbg.DBG_Hooks):
            def __init__(self):
                super().__init__()
                self.info = {}

            def dbg_process_exit(self, pid, tid, ea, exit_code):
                self.info["status"] = "exited"
                self.info["exit_code"] = exit_code
                try:
                    self.unhook()
                except Exception:
                    pass
                exit_event.set()

        hook = _ExitHook()
        hook.hook()
        exit_event._dbg_hook = hook  # prevent GC

    _setup.__name__ = "dbg_exit_setup"
    sync_wrapper(_setup, timeout_override=5.0)

    # exit_process in background thread (may block on dialogs)
    exit_q = queue.Queue()

    def _do_exit_thread():
        def _do_exit():
            try:
                idaapi.exit_process()
                exit_q.put(None)
            except Exception as e:
                exit_q.put(e)
        idaapi.execute_sync(_do_exit, idaapi.MFF_WRITE)

    t = threading.Thread(target=_do_exit_thread, daemon=True)
    t.start()

    # Wait for process exit notification
    if not exit_event.wait(timeout=_DBG_EXIT_TIMEOUT):
        if exit_q.empty():
            raise IDAError(
                "Debugger exit blocked by a dialog in IDA. "
                "Please handle it and try again."
            )
        raise IDAError("Debugger exit timed out.")

    # Return exit info (hook already unhooked itself)
    def _phase3():
        hook = getattr(exit_event, '_dbg_hook', None)
        info = hook.info if hook else {}
        return dict(info)

    _phase3.__name__ = "dbg_exit_phase3"
    return sync_wrapper(_phase3, timeout_override=5.0)


def _dbg_action_wait(action_name, action_fn, timeout=_DBG_ACTION_TIMEOUT):
    """Execute a debugger action and wait for process to suspend or exit.

    Used by continue/step/run_to. Sets up a DBG_Hooks listener, runs the
    action on the main thread, then waits for suspend_process or process_exit.
    Returns a dict with status and IP (if suspended).
    """
    suspend_event = threading.Event()

    def _setup_and_run():
        dbg_ensure_running()

        class _ActionHook(ida_dbg.DBG_Hooks):
            def __init__(self):
                super().__init__()
                self.info = {}

            def _finish(self):
                try:
                    self.unhook()
                except Exception:
                    pass

            def dbg_suspend_process(self):
                self.info["status"] = "suspended"
                ip = ida_dbg.get_ip_val()
                if ip is not None:
                    self.info["ip"] = hex(ip)
                self._finish()
                suspend_event.set()

            def dbg_process_exit(self, pid, tid, ea, exit_code):
                self.info["status"] = "exited"
                self.info["exit_code"] = exit_code
                self._finish()
                suspend_event.set()

            def dbg_exception(self, pid, tid, ea, exc_code,
                              exc_can_cont, exc_ea, exc_info):
                self.info["exception_addr"] = hex(exc_ea)
                self.info["exception_code"] = exc_code
                return 0  # use default handler

        hook = _ActionHook()
        hook.hook()
        suspend_event._dbg_hook = hook

        # Execute the action on the main thread (fast, no dialog risk)
        try:
            ok = action_fn()
        except Exception:
            hook.unhook()
            raise
        if not ok:
            hook.unhook()
            raise IDAError(f"Failed to {action_name}")

    _setup_and_run.__name__ = f"dbg_{action_name}"
    sync_wrapper(_setup_and_run, timeout_override=5.0)

    # Wait for suspend/exit notification
    if suspend_event.wait(timeout=timeout):
        hook = getattr(suspend_event, '_dbg_hook', None)
        return hook.info if hook else {"status": "unknown"}

    # Timeout — process still running, clean up hook
    def _cleanup():
        hook = getattr(suspend_event, '_dbg_hook', None)
        if hook:
            try:
                hook.unhook()
            except Exception:
                pass

    _cleanup.__name__ = f"dbg_{action_name}_cleanup"
    try:
        sync_wrapper(_cleanup, timeout_override=2.0)
    except Exception:
        pass

    return {"status": "running"}


@ext("dbg")
@unsafe
@tool
def dbg_continue():
    """Continue debugger"""
    return _dbg_action_wait("continue", idaapi.continue_process)


@ext("dbg")
@unsafe
@tool
def dbg_run_to(
    addr: Annotated[str, "Target address (hex or decimal, e.g. 0x401000)"],
):
    """Run to address"""
    def _action():
        ea = parse_address(addr)
        return idaapi.run_to(ea)
    return _dbg_action_wait("run_to", _action)


@ext("dbg")
@unsafe
@tool
def dbg_step_into():
    """Step into"""
    return _dbg_action_wait("step_into", idaapi.step_into)


@ext("dbg")
@unsafe
@tool
def dbg_step_over():
    """Step over"""
    return _dbg_action_wait("step_over", idaapi.step_over)


# ============================================================================
# Breakpoint Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_bps():
    """List breakpoints"""
    return list_breakpoints()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_add_bp(
    addrs: Annotated[list[str] | str, "Address(es) (hex or decimal, e.g. 0x401000). Comma-separated string or list"],
) -> list[dict]:
    """Add breakpoints"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
                results.append({"addr": addr, "ok": True})
            else:
                breakpoints = list_breakpoints()
                for bpt in breakpoints:
                    if bpt["addr"] == hex(ea):
                        results.append({"addr": addr, "ok": True})
                        break
                else:
                    results.append({"addr": addr, "error": "Failed to set breakpoint"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_delete_bp(
    addrs: Annotated[list[str] | str, "Address(es) (hex or decimal, e.g. 0x401000). Comma-separated string or list"],
) -> list[dict]:
    """Delete breakpoints"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.del_bpt(ea):
                results.append({"addr": addr, "ok": True})
            else:
                results.append({"addr": addr, "error": "Failed to delete breakpoint"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_toggle_bp(items: Annotated[list[BreakpointOp] | BreakpointOp, "{addr, enabled} object(s), e.g. {addr: '0x401000', enabled: true}"]) -> list[dict]:
    """Enable/disable breakpoints"""

    items = normalize_dict_list(items)

    results = []
    for item in items:
        addr = item.get("addr", "")
        enable = item.get("enabled", True)

        try:
            ea = parse_address(addr)
            if idaapi.enable_bpt(ea, enable):
                results.append({"addr": addr, "ok": True})
            else:
                results.append(
                    {
                        "addr": addr,
                        "error": f"Failed to {'enable' if enable else 'disable'} breakpoint",
                    }
                )
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


# ============================================================================
# Register Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_all() -> list[ThreadRegisters]:
    """Get all registers"""
    result: list[ThreadRegisters] = []
    dbg = dbg_ensure_running()
    for thread_index in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(thread_index)
        result.append(_get_registers_for_thread(dbg, tid))
    return result


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_remote(
    tids: Annotated[list[int] | int, "Thread ID(s) to get registers for"],
) -> list[dict]:
    """Get thread registers"""
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_running()
    available_tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    results = []

    for tid in tids:
        try:
            if tid not in available_tids:
                results.append(
                    {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                )
                continue
            regs = _get_registers_for_thread(dbg, tid)
            results.append({"tid": tid, "regs": regs})
        except Exception as e:
            results.append({"tid": tid, "regs": None, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs() -> ThreadRegisters:
    """Get current thread registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    return _get_registers_for_thread(dbg, tid)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_gpregs_remote(
    tids: Annotated[list[int] | int, "Thread ID(s) to get GP registers for"],
) -> list[dict]:
    """Get GP registers for threads"""
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_running()
    available_tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    results = []

    for tid in tids:
        try:
            if tid not in available_tids:
                results.append(
                    {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                )
                continue
            regs = _get_registers_general_for_thread(dbg, tid)
            results.append({"tid": tid, "regs": regs})
        except Exception as e:
            results.append({"tid": tid, "regs": None, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_gpregs() -> ThreadRegisters:
    """Get current thread GP registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    return _get_registers_general_for_thread(dbg, tid)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_named_remote(
    thread_id: Annotated[int, "Thread ID"],
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
) -> ThreadRegisters:
    """Get specific thread registers"""
    dbg = dbg_ensure_running()
    if thread_id not in [
        ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())
    ]:
        raise IDAError(f"Thread with ID {thread_id} not found")
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, thread_id, names)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_named(
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
) -> ThreadRegisters:
    """Get specific current thread registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, tid, names)


# ============================================================================
# Call Stack Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_stacktrace() -> list[dict[str, str]]:
    """Get call stack"""
    dbg_ensure_running()
    callstack = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()

        if not ida_dbg.collect_stack_trace(tid, trace):
            return []
        for frame in trace:
            frame_info = {
                "addr": hex(frame.callea),
            }
            try:
                module_info = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, module_info):
                    frame_info["module"] = os.path.basename(module_info.name)
                else:
                    frame_info["module"] = "<unknown>"

                name = (
                    ida_name.get_nice_colored_name(
                        frame.callea,
                        ida_name.GNCN_NOCOLOR
                        | ida_name.GNCN_NOLABEL
                        | ida_name.GNCN_NOSEG
                        | ida_name.GNCN_PREFDBG,
                    )
                    or "<unnamed>"
                )
                frame_info["symbol"] = name

            except Exception as e:
                frame_info["module"] = "<error>"
                frame_info["symbol"] = str(e)

            callstack.append(frame_info)

    except Exception as e:
        raise IDAError(f"Failed to collect stack trace: {e}")
    return callstack


# ============================================================================
# Debugger Memory Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_read(regions: Annotated[list[MemoryRead] | MemoryRead, "{addr, size} object(s), e.g. {addr: '0x401000', size: 16}"]) -> list[dict]:
    """Read debug memory"""

    regions = normalize_dict_list(regions)
    dbg_ensure_running()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            size = region["size"]

            data = idaapi.dbg_read_memory(addr, size)
            if data:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": len(data),
                        "data": data.hex(),
                        "error": None,
                    }
                )
            else:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": 0,
                        "data": None,
                        "error": "Failed to read memory",
                    }
                )

        except Exception as e:
            results.append(
                {"addr": region.get("addr"), "size": 0, "data": None, "error": str(e)}
            )

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_write(regions: Annotated[list[MemoryPatch] | MemoryPatch, "{addr, data} object(s), e.g. {addr: '0x401000', data: '90 90'}"]) -> list[dict]:
    """Write debug memory"""

    regions = normalize_dict_list(regions)
    dbg_ensure_running()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            data = bytes.fromhex(region["data"])

            success = idaapi.dbg_write_memory(addr, data)
            results.append(
                {
                    "addr": region["addr"],
                    "size": len(data) if success else 0,
                    "ok": success,
                    "error": None if success else "Write failed",
                }
            )

        except Exception as e:
            results.append({"addr": region.get("addr"), "size": 0, "error": str(e)})

    return results
