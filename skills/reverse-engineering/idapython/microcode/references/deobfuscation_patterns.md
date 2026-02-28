# Common Obfuscation Patterns & Microcode Solutions

## Pattern 1: Computed Indirect Jumps

### What it looks like (native)
```
; ARM64
MOV  W8, #0xF5
STR  W8, [SP, #var_28]
LDR  W9, [SP, #var_28]
EOR  W9, W9, #0x1234
ADD  X9, X9, X20          ; X20 = base address
BR   X9                   ; indirect jump to computed target

; x86_64
mov  [rbp+var_28], 0F5h
mov  eax, [rbp+var_28]
xor  eax, 1234h
add  rax, r12             ; r12 = base address
jmp  rax                  ; indirect jump
```

### What it looks like (microcode)
```
mov  #0xF5, %r8.4
stx  %r8.4, %sp, #var_28
ldx  %sp, #var_28, %r9.4
xor  %r9.4, #0x1234, %r9.4
add  %r9.8, %r20.8, %r9.8
ijmp %r9.8                 ; ← target: resolve this
```

### Solution: Constant Propagation + m_goto Replacement

1. Walk predecessor blocks collecting register/stack state
2. Evaluate the `m_ijmp` operand symbolically
3. Replace `m_ijmp` with `m_goto` pointing to the resolved block
4. Patch the binary: replace native indirect jump with direct jump
5. NOP junk bytes between the jump and the real target
6. Defer function rebuild via **batch fixup queue** — enqueue all fixups into a
   module-level `_g_fixup_queue` with a single shared `register_timer(100, ...)`.
   Never spawn one timer per fixup (causes timer storms). See
   `references/api_safety.md` → "Batch Fixup Queue" for the pattern

### Key considerations

**API safety**: The decompiler's optimizer callback is the right place for step 1-3. Binary
patching (step 4-5) is also safe here via `patch_byte`. But `del_items`/`create_insn`/`add_func`
(step 6) MUST be deferred to a timer callback.

**Target validation**: Before patching, verify the resolved target is within ±64KB of the function
entry (`MAX_PATCH_DIST = 0x10000`). The optimizer is called at multiple maturity levels, and lower
levels may produce bogus values (e.g., 0x5644BA07 for a function at 0x21068). Rejecting bogus
targets prevents `_collect_original_insns` from iterating billions of addresses.

**Cross-maturity poisoning**: Only add to `_patched_addrs` (the "already processed" set) AFTER
target validation passes. Otherwise, a bogus result at maturity 3 blocks the correct result at
maturity 4. See `maturity_levels.md` → "Cross-Maturity Hazard".

**Cooperative timeout**: `decompile()` is synchronous with no timeout. Set a deadline before
calling it, check in `func()` callback entry (with `_timed_out` short-circuit to avoid
`time.time()` overhead), and check in `_propagate()` every ~16 instructions. See
`../../references/api_safety.md` → "Cooperative Timeout".

---

## Pattern 2: Opaque Predicates

### What it looks like
```
; x86
CMP  eax, eax        ; always equal
JNZ  dead_path        ; never taken
JZ   real_target      ; always taken

; ARM64
CMP  X8, X8
B.NE dead_path        ; never taken
B.EQ real_target      ; always taken
```

Two complementary conditional jumps where one is always taken and the other is dead.

### Detection at binary level

Scan for a flag-setting instruction (CMP, TEST on x86; CMP, CMN, TST on ARM64) followed by
two complementary conditional jumps. Use `ida_ua.decode_insn()` + `ida_allins` for
architecture-aware detection:

```python
def _is_flag_setter(insn):
    """Detect CMP/TEST/CMN/TST instructions."""
    import ida_allins
    if is_arm64:
        return insn.itype in (ida_allins.ARM_cmp, ida_allins.ARM_cmn, ida_allins.ARM_tst)
    return insn.itype in (ida_allins.NN_cmp, ida_allins.NN_test)

def _are_complementary_jcc_x86(insn1, insn2):
    """x86 Jcc pairs have itype difference of 1."""
    return abs(insn1.itype - insn2.itype) == 1

def _are_complementary_bcond_arm64(ea1, ea2):
    """ARM64 B.cond: condition codes differ by lowest bit."""
    val1 = ida_bytes.get_dword(ea1)
    val2 = ida_bytes.get_dword(ea2)
    if (val1 & 0xFF000010) != 0x54000000:
        return False
    if (val2 & 0xFF000010) != 0x54000000:
        return False
    cond1 = val1 & 0xF
    cond2 = val2 & 0xF
    return cond1 ^ cond2 == 1
```

### Solution
NOP the dead-path conditional jump. The decompiler will then see only one path and optimize
the remaining conditional into an unconditional goto.

---

## Pattern 3: Junk Code Insertion

### What it looks like
Random instructions inserted between the indirect jump and the real target:

```
BR   X9              ; indirect jump (will be patched to direct)
; --- junk bytes ---
.byte 0x12, 0x34, ...
MOV  X0, X0          ; meaningless
ADD  X1, X1, #0      ; meaningless
; --- real target ---
STP  X29, X30, [SP, #-0x40]!  ; function prologue or real code
```

### Solution
After resolving the indirect jump target, NOP all bytes between the original jump location
and the real target. This requires knowing the instruction alignment (1 byte for x86, 4 bytes
for ARM64).

### ARM64 Special Case: Literal Pool Loads
On ARM64, `LDRSW` and `LDR` instructions with PC-relative literal pool addressing may reference
data within the junk byte region. If you NOP the junk bytes, these literal loads will reference
NOP instructions instead of their data. You must also NOP these literal load instructions:

```python
def nop_literal_loads_in_range(start, end):
    """NOP any LDRSW/LDR literal instructions whose pool falls in [start, end)."""
    # Scan a wider area (the entire function) for literal loads
    for ea in range(func_start, func_end, 4):
        val = ida_bytes.get_dword(ea)
        # LDRSW literal: top byte 0x98
        if (val >> 24) & 0xFF == 0x98:
            imm19 = (val >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            pool_addr = ea + (imm19 << 2)
            if start <= pool_addr < end:
                nop_at(ea)  # NOP the literal load too
```

---

## Pattern 4: OLLVM Control Flow Flattening (CFF / -fla)

The most iconic and destructive OLLVM pass. It completely dismantles the original control flow
structure of a function, rebuilding it with a dispatcher (main dispatch block) + state variable.

### Native Code Structure

```
func_entry:
    mov  [rbp+state_var], INITIAL_STATE   ; initialize state variable

dispatcher:                                ; all real blocks eventually jump back here
    mov  eax, [rbp+state_var]
    cmp  eax, STATE_A
    je   block_A
    cmp  eax, STATE_B
    je   block_B
    cmp  eax, STATE_C
    je   block_C
    jmp  block_default                     ; or switch/jump table

block_A:
    ; ... real code ...
    mov  [rbp+state_var], NEXT_STATE_AFTER_A
    jmp  dispatcher

block_B:
    ; ... real code ...
    ; conditional branch: set different next_state based on condition
    cmovne eax, STATE_X
    cmove  eax, STATE_Y
    mov  [rbp+state_var], eax
    jmp  dispatcher
```

### Microcode Pattern

```
; Entry block
mov  #INIT_STATE.4, stk_var.4

; Dispatcher block (characteristics: many jz/jnz or jtbl, multiple successors)
ldx  %sp, #stk_var, %r8.4
jz   %r8.4, #STATE_A.4, blk_A
jz   %r8.4, #STATE_B.4, blk_B
jz   %r8.4, #STATE_C.4, blk_C
goto blk_default

; Real block (characteristics: writes state_var at tail + goto dispatcher)
; ... real instructions ...
mov  #NEXT_STATE.4, %r8.4
stx  %r8.4, %sp, #stk_var
goto blk_dispatcher
```

### Detection at Microcode Level

```python
def find_cff_dispatcher(mba):
    """Identify CFF dispatcher blocks.

    Characteristics:
    1. Many successors (nsucc >= 3, typically >= 5)
    2. Many predecessors (many real blocks jump back)
    3. Loads state from the same stack variable/register at the start
    4. Contains a series of jz/jnz comparing the same state variable against different constants
    """
    candidates = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        n_succ = len(list(blk.succset))
        n_pred = len(list(blk.predset))

        if n_succ < 3 or n_pred < 3:
            continue

        # Check if block starts with ldx/mov loading state, followed by multiple jz/jnz
        state_loads = 0
        cmp_jumps = 0
        insn = blk.head
        while insn:
            if insn.opcode in (ida_hexrays.m_ldx, ida_hexrays.m_mov):
                state_loads += 1
            if insn.opcode in (ida_hexrays.m_jz, ida_hexrays.m_jnz,
                               ida_hexrays.m_jtbl):
                cmp_jumps += 1
            insn = insn.next

        if cmp_jumps >= 2:
            candidates.append((i, n_succ, n_pred, cmp_jumps))

    return candidates

def find_state_variable(dispatcher_blk):
    """Extract the state variable's stack offset/register from the dispatcher block.

    Looks for the ldx/mov at the dispatcher's start whose destination register
    is used by all subsequent jz instructions.
    """
    insn = dispatcher_blk.head
    while insn:
        if insn.opcode == ida_hexrays.m_ldx and insn.d.t == ida_hexrays.mop_r:
            # Candidate state register
            state_reg = insn.d.r
            # Verify all subsequent jz instructions compare this register
            check = insn.next
            all_match = True
            while check:
                if check.opcode in (ida_hexrays.m_jz, ida_hexrays.m_jnz):
                    if check.l.t != ida_hexrays.mop_r or check.l.r != state_reg:
                        all_match = False
                        break
                check = check.next
            if all_match:
                # Return the state source (stack offset)
                if insn.r.t == ida_hexrays.mop_S:
                    return {'type': 'stack', 'off': insn.r.s.off, 'reg': state_reg}
            break
        insn = insn.next
    return None

def collect_state_transitions(mba, dispatcher_serial, state_info):
    """Collect state_var values written by each real block to map original control flow.

    Returns: {block_serial: [next_state_value, ...]}
    Unconditional blocks have one next_state; conditional blocks have two.
    """
    transitions = {}
    for i in range(mba.qty):
        if i == dispatcher_serial:
            continue
        blk = mba.get_mblock(i)

        # Check if this block jumps back to dispatcher
        jumps_to_dispatcher = False
        for s in blk.succset:
            if s == dispatcher_serial:
                jumps_to_dispatcher = True
                break
        if not jumps_to_dispatcher:
            continue

        # Scan the block for writes to state_var
        next_states = []
        insn = blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_stx:
                # Stack write: stx val, seg, stk_var
                if (state_info['type'] == 'stack' and
                    insn.d.t == ida_hexrays.mop_S and
                    insn.d.s.off == state_info['off']):
                    val = eval_operand(insn.l, PropState())
                    if val is not None:
                        next_states.append(val)
            elif insn.opcode == ida_hexrays.m_mov:
                # mov to state register
                if (insn.d.t == ida_hexrays.mop_r and
                    insn.d.r == state_info['reg']):
                    val = eval_operand(insn.l, PropState())
                    if val is not None:
                        next_states.append(val)
            insn = insn.next

        if next_states:
            transitions[i] = next_states

    return transitions
```

### Solution: Deflattening

The core idea is to **reconstruct the original control flow graph**, eliminating the dispatcher:

```python
def deflatten_cff(mba, dispatcher_serial, state_info, transitions):
    """Restore CFF-flattened code to direct control flow.

    Steps:
    1. Build state_value -> block_serial mapping (extracted from dispatcher's jz instructions)
    2. For each real block, use its next_state to find the target block
    3. Replace "stx next_state + goto dispatcher" with "goto target_block"
    4. For conditional blocks, preserve the condition with both branches pointing to their targets
    5. Remove the dispatcher block (or let Hex-Rays DCE handle it automatically)
    """
    # Step 1: state_value -> target block
    state_to_block = {}
    insn = mba.get_mblock(dispatcher_serial).head
    while insn:
        if insn.opcode == ida_hexrays.m_jz:
            if insn.r.t == ida_hexrays.mop_n and insn.d.t == ida_hexrays.mop_b:
                state_val = insn.r.nnn.value
                target_blk = insn.d.b
                state_to_block[state_val] = target_blk
        insn = insn.next

    changed = 0
    # Step 2-3: Rewrite the tail of each real block
    for blk_serial, next_states in transitions.items():
        blk = mba.get_mblock(blk_serial)

        if len(next_states) == 1:
            # Unconditional jump: goto target block directly
            target = state_to_block.get(next_states[0])
            if target is not None:
                # Find goto dispatcher, change to goto target
                tail = blk.tail
                if tail and tail.opcode == ida_hexrays.m_goto:
                    tail.l.make_blkref(target)
                    # NOP the state_var write instructions
                    _nop_state_writes(blk, state_info)
                    blk.mark_lists_dirty()
                    changed += 1

        elif len(next_states) == 2:
            # Conditional jump: requires more precise handling
            # Find the conditional branch instruction (jcnd/jnz/jz) and two state writes
            # Convert to jcnd -> target_true, goto target_false
            pass  # Implementation depends on the specific conditional branch pattern

    return changed
```

### CFF Challenges

1. **Conditional block state writes**: OLLVM uses `cmov` / `csel` or phi-like patterns to set
   different next_state values based on conditions. At the microcode level this may manifest as
   nested `m_jcnd` or `m_mov` + conditional operations
2. **Nested flattening**: Some variants use multi-level dispatchers or dynamically computed state
3. **Combined with BCF**: Bogus conditions may be inserted before real blocks; BCF must be
   removed before CFF deflattening
4. **Switch-based vs If-else**: The dispatcher may use `m_jtbl` (jump table) or a series of
   `m_jz`/`m_jnz`; both forms must be handled

---

## Pattern 5: OLLVM Bogus Control Flow (BCF / -bcf)

BCF inserts an **always-true (or always-false) opaque predicate** before each basic block,
creating fake control flow branches. Similar to Pattern 2's opaque predicates but more systematic.

### Classic OLLVM BCF Opaque Predicates

OLLVM uses predicates based on mathematical identities by default:

```c
// Always true: (x * (x - 1)) % 2 == 0  (product of consecutive integers is always even)
// Always true: (x^2 + x) % 2 == 0
if ((y * (y - 1)) % 2 == 0) {  // always true
    real_code();
} else {
    cloned_garbage();            // never-executed cloned+mutated code
}
```

### Microcode Pattern

```
; Compute y*(y-1) % 2
ldx  %sp, #var_y, %r8.4
sub  %r8.4, #1.4, %r9.4           ; y - 1
mul  %r8.4, %r9.4, %r10.4         ; y * (y - 1)
and  %r10.4, #1.4, %r11.4         ; % 2 via AND 1
jnz  %r11.4, #0.4, blk_bogus      ; never taken (result is always 0)
; fall through to real code

; Or a more optimized version:
; jcnd (sub-expression), blk_bogus
```

### Detection Strategies

```python
def detect_bcf_opaque_predicates(mba):
    """Detect OLLVM BCF opaque predicates.

    Strategy 1: Pattern matching - identify known mathematical identities like y*(y-1)%2==0
    Strategy 2: Abstract interpretation - perform simple value range analysis on the predicate
    Strategy 3: Use mba.get_valranges() to let Hex-Rays compute it
    """
    results = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.type != ida_hexrays.BLT_2WAY:
            continue

        tail = blk.tail
        if not tail or tail.opcode not in (
            ida_hexrays.m_jnz, ida_hexrays.m_jz,
            ida_hexrays.m_jcnd,
        ):
            continue

        # Strategy 1: Check for mul+and#1 or mul+umod#2 pattern
        if _has_mul_mod2_pattern(blk):
            results.append({
                'block': i,
                'type': 'bcf_mul_mod2',
                'always_true_succ': _determine_true_branch(blk),
            })
            continue

        # Strategy 3: Use Hex-Rays value range analysis
        # (available at MMAT_GLBOPT or higher maturity)
        # valranges can tell you the possible value range of an operand
        # If the jcnd condition operand range is [0,0], the condition is always false

    return results

def _has_mul_mod2_pattern(blk):
    """Check if the block contains x*(x-1) % 2 or x*(x+1) % 2 pattern."""
    has_mul = False
    has_mod2 = False
    insn = blk.head
    while insn:
        if insn.opcode == ida_hexrays.m_mul:
            has_mul = True
        if insn.opcode == ida_hexrays.m_and:
            # AND x, #1 is equivalent to MOD 2
            if insn.r.t == ida_hexrays.mop_n and insn.r.nnn.value == 1:
                has_mod2 = True
        if insn.opcode == ida_hexrays.m_umod:
            if insn.r.t == ida_hexrays.mop_n and insn.r.nnn.value == 2:
                has_mod2 = True
        insn = insn.next
    return has_mul and has_mod2
```

### Solution

```python
def remove_bcf_predicate(mba, block_serial, always_true_succ):
    """Remove a BCF opaque predicate, converting a 2-way block to 1-way.

    Replaces the conditional jump with an unconditional goto to the always-true branch.
    The bogus branch will be cleaned up by subsequent DCE (dead code elimination).
    """
    blk = mba.get_mblock(block_serial)
    tail = blk.tail

    # Replace conditional jump with unconditional goto
    tail.opcode = ida_hexrays.m_goto
    tail.l.make_blkref(always_true_succ)
    tail.r.t = ida_hexrays.mop_z
    tail.d.t = ida_hexrays.mop_z

    # NOP the predicate computation instructions (mul, sub, and, etc.)
    insn = blk.head
    while insn:
        next_i = insn.next
        if insn.opcode in (ida_hexrays.m_mul, ida_hexrays.m_umod,
                           ida_hexrays.m_sub, ida_hexrays.m_add):
            # Only NOP predicate-related instructions; requires def-use analysis
            # Simple approach: if an instruction's result is only used by jcnd/jnz, it's part of the predicate
            blk.make_nop(insn)
        insn = next_i

    blk.mark_lists_dirty()
    # Hex-Rays DCE will automatically remove unreachable bogus blocks
    return 1
```

### BCF Challenges

1. **Bogus blocks clone real code**: BCF doesn't insert random garbage; it **clones real blocks
   with small mutations**, so you can't simply judge by "code looks like garbage"
2. **Custom predicates**: OLLVM allows replacing the default `y*(y-1)%2` predicate with more
   complex mathematical expressions
3. **Nested BCF**: Applying BCF multiple times causes exponential growth of fake branches
4. **Combined with CFF**: When BCF is applied after flattening, bogus blocks also appear within
   the dispatcher structure

---

## Pattern 6: OLLVM Instruction Substitution (SUB / -sub)

Replaces simple arithmetic/logic operations with equivalent but more complex expressions.

### Common Substitution Rules

| Original | Substituted Form | Microcode Representation |
|----------|------------------|--------------------------|
| `a + b` | `a - (-b)` | `m_neg` + `m_sub` |
| `a + b` | `-(-a - b)` | `m_neg` + `m_sub` + `m_neg` |
| `a + b` | `(a ^ b) + 2*(a & b)` | `m_xor` + `m_and` + `m_shl` + `m_add` |
| `a - b` | `a + (-b)` | `m_neg` + `m_add` |
| `a - b` | `-(-a + b)` | `m_neg` + `m_add` + `m_neg` |
| `a & b` | `(a ^ ~b) & a` | `m_bnot` + `m_xor` + `m_and` |
| `a & b` | `~(~a \| ~b)` | `m_bnot` × 3 + `m_or` |
| `a \| b` | `(a & b) \| (a ^ b)` | `m_and` + `m_xor` + `m_or` |
| `a ^ b` | `(a \| b) & ~(a & b)` | `m_or` + `m_and` + `m_bnot` + `m_and` |
| `a ^ b` | `(~a & b) \| (a & ~b)` | `m_bnot` × 2 + `m_and` × 2 + `m_or` |

### Detection at Microcode Level

```python
# Match known substitution patterns at MMAT_LOCOPT stage

SUB_PATTERNS = [
    # a + b -> a - (-b): check for neg + sub where sub.l == original a
    {
        'name': 'add_via_neg_sub',
        'match': lambda insn: (
            insn.opcode == ida_hexrays.m_sub and
            insn.r.t == ida_hexrays.mop_d and
            insn.r.d.opcode == ida_hexrays.m_neg
        ),
        'simplify': lambda insn: _simplify_to_add(insn),
    },
    # a & b -> ~(~a | ~b): check for bnot + or + bnot chain
    {
        'name': 'and_via_demorgan',
        'match': lambda insn: (
            insn.opcode == ida_hexrays.m_bnot and
            insn.l.t == ida_hexrays.mop_d and
            insn.l.d.opcode == ida_hexrays.m_or and
            _both_operands_are_bnot(insn.l.d)
        ),
        'simplify': lambda insn: _simplify_to_and(insn),
    },
]

class SubstitutionSimplifier(ida_hexrays.optinsn_t):
    """optinsn_t is better suited than optblock_t for instruction-level pattern matching."""

    def func(self, blk, insn):
        for pattern in SUB_PATTERNS:
            if pattern['match'](insn):
                return pattern['simplify'](insn)
        return 0
```

### Solution

The good news about instruction substitution is that **Hex-Rays' own optimizer can handle most
cases**. At the MMAT_GLBOPT stage, many substitutions are automatically reversed by standard
peephole optimizations and constant folding.

Only a few complex substitutions require manual handling. Recommended strategy:

1. **Don't handle SUB first**: Decompile directly and check the Hex-Rays auto-optimization results
2. **Write optinsn_t only for residual complex expressions**: Match known OLLVM substitution
   patterns and simplify
3. **Do it at MMAT_LOCOPT stage**: The earlier the simplification, the more downstream
   optimizations benefit

```python
def _simplify_to_add(insn):
    """Simplify sub(a, neg(b)) to add(a, b)."""
    # insn: m_sub l=a, r=d(m_neg l=b) -> d
    neg_insn = insn.r.d  # m_neg
    b_operand = neg_insn.l  # original b

    insn.opcode = ida_hexrays.m_add
    # Replace r from sub-instruction with direct reference to b
    insn.r.swap(b_operand)  # must handle mop_t ownership correctly
    return 1
```

### SUB Challenges

1. **Multi-level nesting**: OLLVM can apply substitutions multiple times to the same operation,
   producing deeply nested expression trees
2. **Mixed with constants**: Substituted expressions may interleave with real constant operations,
   making them hard to distinguish
3. **mop_d nesting depth**: In microcode, `mop_d` can nest arbitrarily deep; pattern matching
   must be recursive

---

## Pattern 7: OLLVM String Encryption (-sobf)

Some OLLVM variants support string encryption: all string constants are encrypted at compile time
and decrypted at runtime via a decryption function.

### Microcode Pattern

```
; Called during global initialization or first use to decrypt
call  decrypt_string, {#encrypted_data, #key, #len}
; Subsequently references the decrypted string via a global variable
ldx   ds, #g_decrypted_str, %r8.8
```

### Detection

```python
def find_string_decrypt_calls(mba):
    """Find potential string decryption calls.

    Characteristics:
    1. Calls a small function with a global data address + length/key as arguments
    2. The called function contains a XOR/ADD/SUB loop internally
    3. Result is stored into a global variable
    """
    suspects = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        insn = blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_call:
                # Check if arguments include a global data address
                if _call_has_global_data_arg(insn):
                    suspects.append({
                        'block': i,
                        'ea': insn.ea,
                        'callee': insn.l,
                    })
            insn = insn.next
    return suspects
```

### Solution

String encryption is better solved at the binary level rather than the microcode level:

1. **Emulation**: Use Unicorn/QEMU to execute the decryption function and obtain plaintext strings
2. **IDB annotation**: Set string comments at the decrypted global variable addresses
3. **Patch**: Write the decrypted plaintext directly into the IDB (optional)

---

## Pattern 5: MBA-Level Function Boundary Issues

### The problem
After patching indirect jumps, the original function boundaries in IDA are often wrong. The
function may be too short (missing the real target) or split across multiple ranges.

### Solution: Use m_ret for Architecture-Independent Boundary Detection

Scan all microcode blocks for `m_ret` instructions to find the true function end:

```python
def find_true_func_end(mba, patch_target_ea):
    """After patching, find where the function really ends."""
    max_end = 0
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.start < patch_target_ea:
            continue
        insn = blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_ret:
                max_end = max(max_end, blk.end)
            insn = insn.next
    return max_end if max_end > 0 else None
```

Then rebuild the function in a deferred timer:
```python
def rebuild_func(start_ea, end_ea):
    ida_funcs.del_func(start_ea)
    ida_bytes.del_items(start_ea, 0, end_ea - start_ea)
    # Re-create instructions
    ea = start_ea
    while ea < end_ea:
        length = ida_ua.create_insn(ea)
        if length <= 0:
            ea += alignment
        else:
            ea += length
    ida_funcs.add_func(start_ea, end_ea)
```

---

## Pattern 8: Residual JUMPOUT Fix-Up Strategies

When the microcode-level constant propagation succeeds for most cases but a few functions
still show `JUMPOUT(...)` in the decompiler output, the root causes are usually at the IDB
level rather than the microcode level. Six fix-up strategies cover all known residual cases:

### Strategy A: Define Undefined Code Bytes at Target

**Symptom**: JUMPOUT target is inside the function but `is_code(flags) == False`.

**Root cause**: IDA's auto-analysis didn't define the bytes as code instructions, so the
decompiler can't include them in any microcode block.

```python
# CRITICAL: Use DELIT_SIMPLE flag, not flag=0
ida_bytes.del_items(tgt, ida_bytes.DELIT_SIMPLE, 32)
ida_ua.create_insn(tgt)
# Continue defining from there until reaching already-defined code
```

**Key lesson**: `del_items(ea, 0, size)` is not always thorough enough — `DELIT_SIMPLE`
ensures complete cleanup of IDB item markers so `create_insn` can succeed.

### Strategy B: Extend Function Boundary

**Symptom**: JUMPOUT target equals `func_end` or is slightly beyond it, no other function overlaps.

```python
# Find new end: ret instruction or next function boundary
new_end = find_ret_or_overlap_boundary(func_end)
ida_funcs.del_func(start)
ida_funcs.add_func(start, new_end)
```

### Strategy C: Patch Indirect Jump to Direct Jump

**Symptom**: Plugin propagation gives garbage address (e.g., `0xFFFFFFFFFFFFC12C`), but the
decompiler's JUMPOUT target looks correct. Typically because NOP-patched bytes are read as constants.

```python
# Find the x86 `jmp r15` (3 bytes) and patch to `jmp rel32` (5 bytes)
import struct
rel32 = target - (jmp_ea + 5)
patch = b'\xE9' + struct.pack('<i', rel32)
for i, b in enumerate(patch):
    ida_bytes.patch_byte(jmp_ea + i, b)
# NOP fill the gap between instruction end and target
```

**Warning**: NOP zone end may have a `0x00` padding byte — verify the real instruction start
and adjust the target address accordingly.

### Strategy D: Convert Tail-Call `jmp` to `call`

**Symptom**: Function ends with `jmp _target` (tail-call) but target is inside another function.

```python
# x86: E9 (jmp rel32) → E8 (call rel32), same offset encoding
# The ret instruction already follows at func_end
ida_bytes.patch_byte(jmp_ea, 0xE8)
```

### Strategy E: Create Missing Target Function

**Symptom**: Tail-call target has a valid function prologue but no IDA function defined.

```python
ida_bytes.del_items(target_ea, 0, end - target_ea)
# Re-create instructions
ea = target_ea
while ea < end:
    length = ida_ua.create_insn(ea)
    ea += max(length, 1)
ida_funcs.add_func(target_ea, end)
```

### Strategy F: Split Mis-Merged Functions (ARM64)

**Symptom**: Tail-call `B _target` goes into a function that has been incorrectly merged
with another. The target address starts with a proper prologue (e.g., `STP X26,X25,[SP,...]`),
preceded by a branch instruction that ends the previous code path.

```python
# Truncate parent function at the prologue boundary
ida_funcs.del_func(parent_start)
ida_funcs.add_func(parent_start, prologue_ea)
# Create new function at the prologue
ida_funcs.add_func(prologue_ea, new_end)
```

### Iterative Application

A single function may have **multiple layers of obfuscation**. After fixing one JUMPOUT,
re-decompiling may reveal additional ones (as the decompiler now reaches further code).
Always re-scan after fixes and iterate until stable.

---

## General Best Practices

1. **Guard against re-application**: Use a set to track already-patched addresses
2. **Log everything**: Deobfuscation is iterative; detailed logs help debug failures
3. **Preserve original disassembly in comments**: Before patching, save what was there
4. **Test on multiple architectures**: If your target supports both x86 and ARM, test both
5. **Handle partial resolution gracefully**: If propagation fails, leave the m_ijmp alone
   rather than corrupting the microcode
6. **Idempotent operations**: Your optimizer may be called multiple times; ensure it handles
   this correctly (e.g., don't try to patch an already-patched address)
7. **Use `DELIT_SIMPLE` for `del_items`**: Default flag=0 may not fully clear IDB markers
8. **Re-scan after each batch of fixes**: New JUMPOUTs may appear as the decompiler reaches
   previously unreachable code
