# Constant Propagation Engine for Microcode

A complete implementation pattern for tracking register/stack values through microcode blocks
to resolve computed targets (e.g., indirect jumps).

## PropState — Symbolic Execution State

```python
class PropState:
    """Symbolic execution state for constant propagation."""
    def __init__(self):
        self.regs = {}           # micro-register → concrete value
        self.stack = {}          # stack offset → concrete value
        self.stk_addr_regs = {}  # micro-register → stack offset it points to

    def set_stk_addr(self, r, stk_off):
        """Record that micro-register *r* holds the ADDRESS of stk[stk_off].
        Also clears any stale concrete value so that ldx through this register
        falls through to the stk_addr resolution path."""
        self.stk_addr_regs[r] = stk_off
        self.regs.pop(r, None)   # ← critical: prevent stale value poisoning
```

Three maps track the state:
- `regs`: Maps micro-register numbers to known concrete values
- `stack`: Maps stack offsets to known concrete values
- `stk_addr_regs`: Tracks registers that hold stack addresses (from LEA-like operations),
  enabling indirect stack access resolution (e.g., `lea rax, [rbp+var]; mov [rax], 5`)

**Important**: When a register is recorded in `stk_addr_regs` (via `set_stk_addr`), its entry
in `regs` MUST be cleared. Otherwise a stale concrete value from an earlier block will shadow
the stack-address path in `eval_operand`, causing `ldx` through that register to read from a
garbage address instead of the stack.

## eval_operand — Evaluate a Microoperand

```python
def eval_operand(op, state):
    """Evaluate an mop_t to a concrete value, or None if unknown."""
    if op.t == ida_hexrays.mop_n:
        return op.nnn.value
    if op.t == ida_hexrays.mop_r:
        return state.regs.get(op.r)
    if op.t == ida_hexrays.mop_S:
        off = op.s.off
        return state.stack.get(off)
    if op.t == ida_hexrays.mop_v:
        # Global variable — read directly from IDB
        return ida_bytes.get_qword(op.g) if op.size == 8 else ida_bytes.get_dword(op.g)
    if op.t == ida_hexrays.mop_d:
        # Sub-instruction — recursively evaluate
        return eval_instruction(op.d, state)
    if op.t == ida_hexrays.mop_a:
        # Address-of — return the address value
        if op.a and hasattr(op.a, 'g'):
            return op.a.g
    return None
```

## eval_instruction — Evaluate a Microinstruction

```python
def eval_instruction(insn, state):
    """Evaluate an minsn_t and return result value, or None."""
    opc = insn.opcode

    # Data movement
    if opc == ida_hexrays.m_mov:
        return eval_operand(insn.l, state)

    # Memory load
    if opc == ida_hexrays.m_ldx:
        seg = eval_operand(insn.l, state)
        off = eval_operand(insn.r, state)
        if off is not None:
            # Stack load via register
            if insn.r.t == ida_hexrays.mop_r and insn.r.r in state.stk_addr_regs:
                stk_off = state.stk_addr_regs[insn.r.r]
                return state.stack.get(stk_off)
            # Global load from IDB
            return read_from_idb(off, insn.d.size)
        return None

    # Binary operations
    BINOPS = {
        ida_hexrays.m_add: lambda a, b: a + b,
        ida_hexrays.m_sub: lambda a, b: a - b,
        ida_hexrays.m_mul: lambda a, b: a * b,
        ida_hexrays.m_xor: lambda a, b: a ^ b,
        ida_hexrays.m_and: lambda a, b: a & b,
        ida_hexrays.m_or:  lambda a, b: a | b,
        ida_hexrays.m_shl: lambda a, b: a << b,
        ida_hexrays.m_shr: lambda a, b: a >> b,
    }
    if opc in BINOPS:
        lv = eval_operand(insn.l, state)
        rv = eval_operand(insn.r, state)
        if lv is not None and rv is not None:
            mask = (1 << (insn.d.size * 8)) - 1
            return BINOPS[opc](lv, rv) & mask
        return None

    # Unary operations
    if opc == ida_hexrays.m_neg:
        val = eval_operand(insn.l, state)
        if val is not None:
            return (-val) & ((1 << (insn.d.size * 8)) - 1)
    if opc == ida_hexrays.m_bnot:
        val = eval_operand(insn.l, state)
        if val is not None:
            return val ^ ((1 << (insn.d.size * 8)) - 1)

    # Size conversions
    if opc == ida_hexrays.m_xdu:  # Zero-extend
        val = eval_operand(insn.l, state)
        if val is not None:
            return val & ((1 << (insn.l.size * 8)) - 1)

    if opc == ida_hexrays.m_xds:  # Sign-extend
        val = eval_operand(insn.l, state)
        if val is not None:
            bits = insn.l.size * 8
            if val & (1 << (bits - 1)):
                val = val - (1 << bits)
            return val & ((1 << (insn.d.size * 8)) - 1)

    if opc == ida_hexrays.m_low:  # Truncate to low bytes
        val = eval_operand(insn.l, state)
        if val is not None:
            return val & ((1 << (insn.d.size * 8)) - 1)

    if opc == ida_hexrays.m_high:  # Extract high bytes
        val = eval_operand(insn.l, state)
        if val is not None:
            shift = (insn.l.size - insn.d.size) * 8
            return (val >> shift) & ((1 << (insn.d.size * 8)) - 1)

    # Arithmetic shift right (preserves sign bit)
    if opc == ida_hexrays.m_sar:
        lv = eval_operand(insn.l, state)
        rv = eval_operand(insn.r, state)
        if lv is not None and rv is not None:
            bits = insn.l.size * 8
            if lv & (1 << (bits - 1)):
                lv = lv - (1 << bits)  # Sign-extend to Python int
            return (lv >> rv) & ((1 << (insn.d.size * 8)) - 1)

    return None
```

## propagate_block — Walk a Block and Update State

The `deadline` parameter enables cooperative timeout: when set to a nonzero `time.time()`
value, the function checks the deadline at entry and periodically (every 16 instructions)
during traversal. Returns `False` if aborted by deadline.

```python
import time as _time

def propagate_block(blk, state, deadline=0):
    """Walk all instructions in a block and update state.
    Returns False if aborted by deadline."""
    if deadline and _time.time() > deadline:
        return False
    insn = blk.head
    _n = 0
    while insn:
        _n += 1
        if deadline and (_n & 15) == 0 and _time.time() > deadline:
            return False
        opc = insn.opcode

        if opc == ida_hexrays.m_mov and insn.d.t == ida_hexrays.mop_r:
            val = eval_operand(insn.l, state)
            if val is not None:
                state.regs[insn.d.r] = val
            # Track stack address registers (LEA-like)
            if insn.l.t == ida_hexrays.mop_a:
                state.set_stk_addr(insn.d.r, insn.l.a)  # clears regs[r] too

        elif opc == ida_hexrays.m_stx:
            # Store to memory — check if storing to stack via register
            val = eval_operand(insn.l, state)
            if val is not None and insn.d.t == ida_hexrays.mop_r:
                if insn.d.r in state.stk_addr_regs:
                    stk_off = state.stk_addr_regs[insn.d.r]
                    state.stack[stk_off] = val
            if val is not None and insn.d.t == ida_hexrays.mop_S:
                state.stack[insn.d.s.off] = val

        elif opc != ida_hexrays.m_nop:
            result = eval_instruction(insn, state)
            if result is not None and insn.d.t == ida_hexrays.mop_r:
                state.regs[insn.d.r] = result
            elif result is not None and insn.d.t == ida_hexrays.mop_S:
                state.stack[insn.d.s.off] = result

        insn = insn.next
    return True
```

## Cross-Block Propagation (Multi-Level BFS)

To resolve an indirect jump whose defining constants may be set several blocks
back, use **multi-level BFS** over the predecessor chain (not just immediate
predecessors). The collected blocks are then sorted into forward (topological)
order for propagation so that values flow correctly from earlier blocks to later
ones.

```python
MAX_PRED_DEPTH = 16   # depth limit to avoid runaway traversal

def resolve_ijmp_target(blk):
    """Resolve an m_ijmp at the end of blk by multi-level backward propagation."""
    ijmp = blk.tail
    if not ijmp or ijmp.opcode != ida_hexrays.m_ijmp:
        return None

    state = PropState()
    mba = blk.mba

    # --- Multi-level BFS over predecessor chain ---
    visited = {blk.serial}
    ordered_preds = []          # BFS order (closest first)
    frontier = list(blk.predset)
    depth = 0

    while frontier and depth < MAX_PRED_DEPTH:
        next_frontier = []
        for ps in frontier:
            if ps in visited:
                continue
            visited.add(ps)
            ordered_preds.append(ps)
            pb = mba.get_mblock(ps)
            next_frontier.extend(pb.predset)
        frontier = next_frontier
        depth += 1

    # Reverse so we propagate from the earliest block to the latest
    ordered_preds.reverse()

    # --- Forward propagation through collected predecessors ---
    for pred_serial in ordered_preds:
        propagate_block(mba.get_mblock(pred_serial), state)

    # Propagate through the current block (up to the ijmp itself)
    propagate_block_until(blk, state, stop_at=ijmp)

    # Evaluate the ijmp operand
    return eval_operand(ijmp.l, state)
```

### Why multi-level?

In obfuscated code, a computed jump may depend on constants
set 3-5 blocks back through a chain like:

```
blk[1]: mov #0xA5, r14         ← constant defined here
blk[2]: first computed jump (already patched)
blk[3]: arithmetic using r14
blk[4]: lea &var_44, rax; store r14 → var_44
blk[5]: ldx var_44; xor; add base; ijmp  ← need to resolve this
```

Single-level predecessor propagation (only blk[4]) would miss the `r14 = 0xA5`
definition in blk[1], causing the resolution to fail or produce a wrong target.

## Replacing m_ijmp with m_goto

```python
def replace_ijmp_with_goto(blk, ijmp_insn, target_ea):
    """Replace m_ijmp with m_goto pointing to the target block."""
    mba = blk.mba
    target_blk_idx = -1
    for i in range(mba.qty):
        b = mba.get_mblock(i)
        if b.start <= target_ea < b.end:
            target_blk_idx = i
            break

    if target_blk_idx < 0:
        return False

    ijmp_insn.opcode = ida_hexrays.m_goto
    ijmp_insn.l.make_blkref(target_blk_idx)
    ijmp_insn.r.t = ida_hexrays.mop_z
    ijmp_insn.d.t = ida_hexrays.mop_z
    blk.mark_lists_dirty()
    return True
```

## Target Validation & Cross-Maturity Safety

Before applying a resolved target (binary patching or microcode replacement), validate it:

```python
MAX_PATCH_DIST = 0x10000  # 64KB — legitimate jump targets are within function neighborhood

def validate_and_patch(self, mba, target_addr, ijmp_ea):
    if ijmp_ea in self._patched_addrs:
        return False
    # Distance check: reject bogus targets from incomplete propagation
    if abs(target_addr - mba.entry_ea) > MAX_PATCH_DIST:
        return False  # don't mark — allow retry at higher maturity
    # Only mark AFTER validation passes
    self._patched_addrs.add(ijmp_ea)
    # ... proceed with patching ...
```

**Why this matters**: The optimizer callback is invoked at multiple maturity levels. At lower
maturity (e.g., MMAT_LOCOPT=3), propagation may produce wrong values because the decompiler
hasn't fully simplified the microcode. If you mark an address as "processed" with a wrong
result, the correct result at a higher maturity (e.g., 4) will be blocked.

Real-world example: A function at `0x21068` produced target `0x5644BA07` at maturity 3
(~1.4GB away — clearly bogus) but correct target `0x21158` at maturity 4. Without distance
validation, `_collect_original_insns(nop_start, 0x5644BA07)` iterated through ~1.4 billion
addresses calling `ida_ua.decode_insn()`, taking 292 seconds.

## Detecting Function Boundaries via m_ret

```python
def find_func_end_from_mba(mba, after_ea):
    """Find function end by scanning for m_ret in microcode blocks."""
    best_end = None
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.start < after_ea:
            continue
        insn = blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_ret:
                if best_end is None or blk.end > best_end:
                    best_end = blk.end
                break
            insn = insn.next
    return best_end
```
