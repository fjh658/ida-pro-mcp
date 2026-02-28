---
name: ida-microcode
description: >
  Hex-Rays microcode API deep-dive for IDA Pro decompiler plugin development. Use this skill whenever the user
  is working with the Hex-Rays microcode intermediate representation — writing optblock_t or optinsn_t optimizers,
  manipulating minsn_t/mop_t objects, implementing constant propagation or pattern matching at microcode level,
  building deobfuscation or optimization passes, or analyzing control flow at the mba_t/mblock_t level. Triggers on:
  microcode, optblock_t, optinsn_t, minsn_t, mop_t, mba_t, mblock_t, mcode_t, MMAT_, microcode_filter_t,
  Hexrays_Hooks, decompiler plugin, microcode optimization, deobfuscation plugin, computed jump resolution,
  indirect jump, opaque predicate, constant propagation, m_ijmp, m_goto, m_jcnd, or any Hex-Rays decompiler
  internals work. This is a sub-skill of the `ida` skill and assumes familiarity with basic IDAPython.
---

# Hex-Rays Microcode API

## What is Microcode?

Hex-Rays translates native instructions into a RISC-like intermediate representation called **microcode**.
Decompilation proceeds through a series of maturity levels, with optimization passes running at each level.
Plugins can hook into this pipeline to add custom transformations — this is how deobfuscation plugins,
type recovery passes, and custom optimizations work.

The microcode is the most powerful extension point of the Hex-Rays decompiler. Understanding it enables
writing plugins that can resolve obfuscated control flow, simplify arithmetic, recover types, and more.

## Architecture

```
Native Code (x86/ARM/MIPS/...)
        │
        ▼
   ┌─────────┐    microcode_filter_t (intercept specific instructions)
   │ Codegen  │◄───────────────────
   └────┬─────┘
        │
        ▼
   ┌─────────────┐
   │ MMAT_GENERATED │  Raw microcode, 1:1 with native
   └────┬─────────┘
        │  preoptimization passes
        ▼
   ┌──────────────────┐
   │ MMAT_PREOPTIMIZED │  Basic simplifications done
   └────┬──────────────┘
        │  local optimization (per-block)
        ▼
   ┌────────────┐     optblock_t.func(blk)  ← YOUR PLUGIN HERE
   │ MMAT_LOCOPT │◄────────────────────────
   └────┬────────┘     optinsn_t.func(blk, ins)
        │
        ▼
   ┌─────────────┐
   │ MMAT_CALLS   │  Call analysis
   └────┬─────────┘
        │
        ▼
   ┌──────────────┐
   │ MMAT_GLBOPT1 │  Global optimization phase 1
   └────┬──────────┘
        │
        ▼
   ┌──────────────┐
   │ MMAT_GLBOPT2 │  Global optimization phase 2
   └────┬──────────┘
        │
        ▼
   ┌──────────────┐
   │ MMAT_GLBOPT3 │  Global optimization phase 3
   └────┬──────────┘
        │
        ▼
   ┌────────────┐
   │ MMAT_LVARS  │  Local variable allocation
   └────┬────────┘
        │
        ▼
   C Pseudocode (ctree)
```

## Core Classes

### mba_t — Microcode Block Array

The top-level container representing one function's microcode. Holds all basic blocks.

```python
mba = blk.mba  # Access from any mblock_t

# Properties
mba.qty          # Number of blocks (int)
mba.entry_ea     # Function entry address
mba.mbr          # Memory address range (mbl_array_t)

# Block access
blk = mba.get_mblock(n)   # Get block by index (0..qty-1)

# Block manipulation
mba.insert_block(n)       # Insert empty block before index n
mba.remove_block(blk)     # Remove a block
mba.split_block(blk, ea)  # Split block at address
mba.copy_block(dst, src)  # Deep-copy block
mba.merge_blocks()        # Merge adjacent 1-way blocks

# Cleanup
mba.remove_empty_and_unreachable_blocks()
mba.mark_chains_dirty()   # Invalidate def-use chains
mba.verify(True)          # Verify consistency (debug builds)

# Searching
mba.find_mop(ctx)         # Search for a specific operand pattern
mba.for_all_insns(visitor)    # Visit all instructions
mba.for_all_topinsns(visitor) # Visit top-level instructions only
mba.for_all_ops(visitor)      # Visit all operands

# Helpers
mba.create_helper_call(...)   # Create a helper function call
```

### mblock_t — Basic Block

One basic block in the microcode. Contains a linked list of microinstructions.

```python
# Instruction traversal
blk.head       # First minsn_t (or None)
blk.tail       # Last minsn_t (or None)
insn = blk.head
while insn:
    # ... process insn ...
    insn = insn.next

# Block properties
blk.serial     # Block index in mba (int)
blk.start      # Start address in binary
blk.end        # End address in binary (exclusive)
blk.type       # BLT_* constant (see below)
blk.flags      # MBL_* flags (see below)
blk.mba        # Parent mba_t

# Control flow — predecessors and successors
blk.predset    # intvec_t of predecessor serial numbers (preferred)
blk.succset    # intvec_t of successor serial numbers
blk.npred()    # Number of predecessors
blk.nsucc()    # Number of successors
blk.pred(i)    # i-th predecessor serial number
blk.succ(i)    # i-th successor serial number

# Built-in iterators (yield mblock_t objects)
for pred_blk in blk.preds():
    pass
for succ_blk in blk.succs():
    pass

# Block queries
blk.is_call_block()         # Contains a call instruction
blk.is_branch()             # Ends with a conditional branch
blk.is_simple_goto_block()  # Contains only a goto
blk.is_simple_jcnd_block()  # Contains only a jcnd + goto

# Instruction manipulation
blk.insert_into_block(new_insn, after_insn)  # Insert instruction
blk.remove_from_block(insn)                   # Remove instruction
blk.make_nop(insn)          # NOP instruction (marks lists dirty!)
blk.make_lists_ready()      # Rebuild def/use lists

# Optimization helpers
blk.mark_lists_dirty()      # Invalidate def/use lists
blk.request_propagation()   # Request another optimization pass
blk.optimize_insn(insn)     # Try to optimize one instruction
blk.optimize_block()        # Optimize entire block

# Value analysis
blk.get_valranges(...)      # Get possible values for an operand

# Visitor pattern
blk.for_all_insns(visitor)  # Visit all instructions in this block
blk.for_all_ops(visitor)    # Visit all operands in this block
```

#### Block Types (BLT_*)

| Constant | Value | Meaning |
|----------|-------|---------|
| `BLT_NONE` | 0 | Undefined |
| `BLT_STOP` | 1 | End block (function return) |
| `BLT_0WAY` | 2 | No successors (e.g., noreturn call) |
| `BLT_1WAY` | 3 | One successor (goto / fallthrough) |
| `BLT_2WAY` | 4 | Two successors (conditional branch) |
| `BLT_NWAY` | 5 | Multiple successors (switch/jump table) |
| `BLT_XTRN` | 6 | External block (imported function) |

#### Block Flags (MBL_*)

| Flag | Meaning |
|------|---------|
| `MBL_PRIV` | Privileged block |
| `MBL_NONFAKE` | Not a fake block |
| `MBL_FAKE` | Fake block (synthesized by decompiler) |
| `MBL_GOTO` | Block ends with goto |
| `MBL_TCAL` | Tail call block |
| `MBL_PUSH` | Contains push instructions |
| `MBL_DMT64` | 64-bit demoted |
| `MBL_COMB` | Combined block |
| `MBL_PROP` | Needs propagation |
| `MBL_DEAD` | Dead block |
| `MBL_LIST` | Lists are ready |
| `MBL_INCONST` | Inconsistent state |
| `MBL_CALL` | Contains call |
| `MBL_BACKPROP` | Backward propagation needed |
| `MBL_NORET` | No return from this block |
| `MBL_DSLOT` | Delay slot (MIPS/SPARC) |
| `MBL_VALRANGES` | Value range analysis done |
| `MBL_KEEP` | Keep this block (don't optimize away) |
| `MBL_INLINED` | Inlined function code |

### minsn_t — Microinstruction

One microcode instruction. Each instruction has an opcode, up to two source operands (l, r),
and one destination operand (d).

```python
# Structure
insn.opcode    # mcode_t enum value
insn.l         # Left operand (mop_t) — first source
insn.r         # Right operand (mop_t) — second source
insn.d         # Destination operand (mop_t)
insn.ea        # Original binary address this came from
insn.next      # Next instruction in block (or None)
insn.prev      # Previous instruction in block (or None)

# Sub-instruction support
# insn.d can itself contain an minsn_t (when d.t == mop_d)
# This creates a tree of nested instructions

# Manipulation
insn._make_nop()           # Convert to NOP (does NOT mark lists dirty)
insn.swap(other_insn)      # Swap two instructions
insn.is_assert()           # Is this an assertion pseudo-insn?

# Comparison
insn.equal_insns(other, eqflags)  # Compare instructions

# Pretty-printing
insn.dstr()                # Get string representation
```

### mop_t — Microoperand

Operands of microinstructions. The `t` field determines the operand type.

```python
# Type field
op.t           # Operand type (mop_* constant)
op.size        # Operand size in bytes

# Type-specific access (check op.t first!)
op.r           # Register number (when t == mop_r)
op.nnn         # Immediate value as mnumber_t (when t == mop_n)
    op.nnn.value   # The actual integer value
op.d           # Sub-instruction minsn_t (when t == mop_d)
op.s           # Stack variable mop_addr_t (when t == mop_S)
op.g           # Global address (when t == mop_v)
op.b           # Block number (when t == mop_b)
op.f           # Function pointer (when t == mop_f)
op.l           # Local variable (when t == mop_l)
op.a           # mop_addr_t containing {base, offset} (when t == mop_a)
op.helper      # Helper function name (when t == mop_h)
op.c           # Case values mcases_t (when t == mop_c)
op.fpc         # Function call info mcallinfo_t (when t == mop_fn)
op.pair        # Pair of operands mop_pair_t (when t == mop_p)
op.scif        # Scattered info (when t == mop_sc)
```

#### Operand Types (mop_*)

| Constant | Value | Description | Access |
|----------|-------|-------------|--------|
| `mop_z` | 0 | No operand (unused slot) | — |
| `mop_r` | 1 | Micro-register | `op.r` |
| `mop_n` | 2 | Immediate number | `op.nnn.value` |
| `mop_str` | 3 | String constant | `op.cstr` |
| `mop_d` | 4 | Nested sub-instruction result | `op.d` (minsn_t) |
| `mop_S` | 5 | Stack variable | `op.s` |
| `mop_v` | 6 | Global variable address | `op.g` |
| `mop_b` | 7 | Block reference (for gotos) | `op.b` |
| `mop_f` | 8 | Function pointer | `op.f` |
| `mop_l` | 9 | Local variable | `op.l` |
| `mop_a` | 10 | Address of (pointer to var) | `op.a` |
| `mop_h` | 11 | Helper function name | `op.helper` |
| `mop_c` | 12 | Case values (for switch) | `op.c` |
| `mop_fn` | 13 | Call info | `op.fpc` |
| `mop_p` | 14 | Pair of operands | `op.pair` |
| `mop_sc` | 15 | Scattered operand | `op.scif` |

## Microcode Opcodes (mcode_t)

### Data Movement
| Opcode | Operands | Semantics |
|--------|----------|-----------|
| `m_nop` | — | No operation |
| `m_mov` | l → d | d = l |
| `m_ldc` | l → d | Load constant |
| `m_ldx` | l, r → d | Load from memory: d = *[l + r] |
| `m_stx` | l, r, d | Store to memory: *[r + d] = l |

### Arithmetic
| Opcode | Operands | Semantics |
|--------|----------|-----------|
| `m_add` | l, r → d | d = l + r |
| `m_sub` | l, r → d | d = l - r |
| `m_mul` | l, r → d | d = l * r |
| `m_udiv` | l, r → d | d = l / r (unsigned) |
| `m_sdiv` | l, r → d | d = l / r (signed) |
| `m_umod` | l, r → d | d = l % r (unsigned) |
| `m_smod` | l, r → d | d = l % r (signed) |
| `m_neg` | l → d | d = -l |

### Bitwise
| Opcode | Operands | Semantics |
|--------|----------|-----------|
| `m_or` | l, r → d | d = l \| r |
| `m_and` | l, r → d | d = l & r |
| `m_xor` | l, r → d | d = l ^ r |
| `m_bnot` | l → d | d = ~l (bitwise NOT) |
| `m_lnot` | l → d | d = !l (logical NOT) |
| `m_shl` | l, r → d | d = l << r |
| `m_shr` | l, r → d | d = l >> r (unsigned / logical) |
| `m_sar` | l, r → d | d = l >> r (signed / arithmetic) |

### Size Conversion
| Opcode | Operands | Semantics |
|--------|----------|-----------|
| `m_xds` | l → d | Sign-extend l to d.size |
| `m_xdu` | l → d | Zero-extend l to d.size |
| `m_low` | l → d | Truncate: d = low bytes of l (d.size < l.size) |
| `m_high` | l → d | High bytes: d = l >> ((l.size - d.size) * 8) |

### Control Flow
| Opcode | Operands | Semantics |
|--------|----------|-----------|
| `m_goto` | l | Unconditional jump to block l.b |
| `m_jcnd` | l, d | Conditional jump: if l then goto d.b |
| `m_jnz` | l, r, d | Jump if not zero: if l != r goto d.b |
| `m_jz` | l, r, d | Jump if zero: if l == r goto d.b |
| `m_jae` | l, r, d | Jump if above or equal (unsigned) |
| `m_jb` | l, r, d | Jump if below (unsigned) |
| `m_ja` | l, r, d | Jump if above (unsigned) |
| `m_jbe` | l, r, d | Jump if below or equal (unsigned) |
| `m_jg` | l, r, d | Jump if greater (signed) |
| `m_jge` | l, r, d | Jump if greater or equal (signed) |
| `m_jl` | l, r, d | Jump if less (signed) |
| `m_jle` | l, r, d | Jump if less or equal (signed) |
| `m_jtbl` | l, r | Switch/jump table |
| `m_ijmp` | l(, d) | Indirect jump: goto *l |

### Function Calls & Return
| Opcode | Operands | Semantics |
|--------|----------|-----------|
| `m_call` | l, d | Direct call: d = call l |
| `m_icall` | l, d | Indirect call: d = call *l |
| `m_ret` | — | Return from function |

### Stack
| Opcode | Operands | Semantics |
|--------|----------|-----------|
| `m_push` | l | Push l onto stack |
| `m_pop` | d | Pop from stack into d |

## Writing an optblock_t Optimizer

This is the most common pattern for microcode plugins. The callback is invoked for each basic block
during local optimization.

```python
import ida_hexrays

class MyOptimizer(ida_hexrays.optblock_t):
    def func(self, blk):
        """Called for each basic block.

        Args:
            blk: mblock_t — the current basic block

        Returns:
            int — non-zero if any changes were made (triggers re-optimization)
        """
        # Check maturity level
        if blk.mba.maturity < ida_hexrays.MMAT_LOCOPT:
            return 0

        changed = 0

        # Walk instructions
        insn = blk.head
        while insn:
            next_insn = insn.next  # Save next before potential modification

            if insn.opcode == ida_hexrays.m_ijmp:
                # Found an indirect jump — try to resolve it
                target = self._resolve_target(blk, insn)
                if target is not None:
                    self._replace_with_goto(blk, insn, target)
                    changed += 1

            insn = next_insn

        return changed

    def _resolve_target(self, blk, insn):
        """Attempt to resolve indirect jump target via constant propagation."""
        # ... implementation ...
        return None

    def _replace_with_goto(self, blk, insn, target_ea):
        """Replace m_ijmp with m_goto to a specific block."""
        # Find or create target block
        target_blk_idx = self._find_block_for_ea(blk.mba, target_ea)
        if target_blk_idx < 0:
            return

        # Modify in place
        insn.opcode = ida_hexrays.m_goto
        insn.l.make_blkref(target_blk_idx)
        insn.r._make_nop()  # Clear unused operand
        insn.d._make_nop()  # Clear unused operand

# Install/uninstall
optimizer = MyOptimizer()
optimizer.install()    # Register with decompiler
# optimizer.remove()  # Unregister
```

### Important: Cross-Maturity & Timeout Considerations

The `func()` callback is invoked at **every maturity level** (MMAT_LOCOPT and above) for each
block. Key pitfalls:

1. **Cross-maturity poisoning**: Propagation can produce different results at different maturity
   levels. If you record "already processed" state based on a wrong result at maturity 3, the
   correct result at maturity 4 will be blocked. **Always validate before marking** (e.g.,
   distance check: target within ±64KB of function). See `references/maturity_levels.md`.

2. **Cooperative timeout**: `decompile()` is synchronous with no timeout. For batch processing,
   set a deadline and check it in `func()`:
   ```python
   def func(self, blk):
       self._func_calls += 1
       if self._timed_out:          # fast short-circuit, no time.time()
           return 0
       if self._deadline and time.time() > self._deadline:
           self._timed_out = True
           return 0
       return self._func_impl(blk)
   ```
   See `../../references/api_safety.md` → "Cooperative Timeout".

## Writing an optinsn_t Optimizer

For instruction-level optimizations (finer granularity than optblock_t):

```python
class MyInsnOptimizer(ida_hexrays.optinsn_t):
    def func(self, blk, insn):
        """Called for each instruction.

        Args:
            blk: mblock_t — containing block
            insn: minsn_t — the instruction to optimize

        Returns:
            int — non-zero if instruction was modified
        """
        if insn.opcode == ida_hexrays.m_add:
            # Example: x + 0 → x
            if insn.r.t == ida_hexrays.mop_n and insn.r.nnn.value == 0:
                insn.opcode = ida_hexrays.m_mov
                insn.r._make_nop()
                return 1
        return 0
```

## Writing a microcode_filter_t

Intercepts specific native instructions during code generation and replaces them with
custom microcode. Useful for handling instructions the decompiler doesn't understand well.

```python
class MyFilter(ida_hexrays.microcode_filter_t):
    def match(self, cdg):
        """Return True if this filter should handle the current instruction."""
        return cdg.insn.itype == some_itype

    def apply(self, cdg):
        """Generate custom microcode for the matched instruction.

        Use cdg (codegen_t) methods to emit microcode:
          cdg.emit(opcode, width, l, r, d, off)
          cdg.load_operand(opnum) — load native operand as micro-operand

        Returns:
            MERR_OK on success
        """
        # ... emit custom microcode ...
        return ida_hexrays.MERR_OK

filter_obj = MyFilter()
ida_hexrays.install_microcode_filter(filter_obj, True)   # Install
# ida_hexrays.install_microcode_filter(filter_obj, False) # Uninstall
```

## Constant Propagation & Deobfuscation Patterns

For implementing constant propagation engines, cross-block value tracking, indirect jump
resolution (m_ijmp → m_goto), and function boundary detection via m_ret, read the detailed
reference files:

- **`references/constant_propagation.md`** — Complete PropState/eval_operand/eval_instruction
  implementation with cross-block propagation and m_ijmp replacement
- **`references/deobfuscation_patterns.md`** — Common obfuscation patterns (computed jumps,
  opaque predicates, junk code, control flow flattening) and their microcode solutions

### Quick Summary

The core pattern for resolving indirect jumps:

1. **PropState** tracks `regs` (micro-register → value), `stack` (offset → value), and
   `stk_addr_regs` (register → stack offset for indirect access)
2. **eval_operand** resolves `mop_n` (immediate), `mop_r` (register), `mop_S` (stack),
   `mop_v` (global from IDB), `mop_d` (sub-instruction), `mop_a` (address)
3. **eval_instruction** handles all arithmetic/bitwise/size-conversion opcodes
4. **propagate_block** walks instructions updating state
5. **Cross-block**: Multi-level BFS predecessor collection (depth limit 16) via
   `blk.predset`, reversed to topological order, then forward propagation.
   When recording stack-address registers (`set_stk_addr`), always clear the
   corresponding entry in `regs` to prevent stale-value poisoning
6. **Replace**: `m_ijmp` → `m_goto` with `insn.l.make_blkref(target_blk_idx)`
7. **Function end**: Scan mba blocks for `m_ret`, take max `blk.end`
8. **Residual fix-ups** (when plugin propagation fails):
   - Define undefined code bytes at target: `del_items(tgt, DELIT_SIMPLE, 32)` + `create_insn(tgt)`
   - Extend function boundary: find ret/overlap boundary → `del_func` + `add_func`
   - Patch indirect jmp to direct: overwrite `jmp reg` (3B) with `E9 rel32` (5B) + NOP gap
   - Convert tail-call: `E9` (jmp) → `E8` (call) single byte, ret already follows
   - Create missing target function: `add_func(target_ea)` when tail-call target has prologue but no func
   - Split mis-merged functions: truncate parent at prologue boundary, `add_func` for new segment

## Hexrays_Hooks Events

For broader decompiler integration beyond optimization:

```python
class MyHooks(ida_hexrays.Hexrays_Hooks):
    def flowchart(self, fc):
        """Before microcode generation — can modify flowchart."""
        return 0

    def microcode(self, mba):
        """After microcode generation — can inspect/modify raw microcode."""
        return 0

    def locopt(self, mba):
        """During local optimization."""
        return 0

    def glbopt(self, mba):
        """During global optimization."""
        return 0

    def maturity(self, cfunc, maturity):
        """When maturity level changes — useful for logging/debugging."""
        return 0

hooks = MyHooks()
hooks.hook()
# hooks.unhook()
```

## Debugging Tips

1. **Print microcode at any maturity level**:
   ```python
   mba.print_(None)  # Print to IDA output window
   ```

2. **Dump a single block**:
   ```python
   insn = blk.head
   while insn:
       print(f"  {insn.ea:#x}: {insn.dstr()}")
       insn = insn.next
   ```

3. **Check operand types**:
   ```python
   MOP_NAMES = {0:"z", 1:"r", 2:"n", 3:"str", 4:"d", 5:"S",
                6:"v", 7:"b", 8:"f", 9:"l", 10:"a", 11:"h",
                12:"c", 13:"fn", 14:"p", 15:"sc"}
   print(f"l.t={MOP_NAMES[insn.l.t]} r.t={MOP_NAMES[insn.r.t]} d.t={MOP_NAMES[insn.d.t]}")
   ```

4. **Verify consistency after changes**:
   ```python
   blk.mba.verify(True)  # Will assert on inconsistencies
   ```

5. **Log optimization activity**:
   ```python
   class VerboseOptimizer(ida_hexrays.optblock_t):
       def func(self, blk):
           print(f"[opt] Block {blk.serial}: {blk.start:#x}-{blk.end:#x}, "
                 f"type={blk.type}, preds={list(blk.predset)}, "
                 f"succs={list(blk.succset)}")
           return 0
   ```

## Reference Files

For detailed reference materials, read:

- **`references/constant_propagation.md`** — Complete constant propagation engine with code
- **`references/mcode_opcodes.md`** — Complete mcode_t opcode table with encoding details
- **`references/maturity_levels.md`** — What happens at each MMAT_* level and what to expect
- **`references/deobfuscation_patterns.md`** — Common obfuscation patterns and microcode solutions
