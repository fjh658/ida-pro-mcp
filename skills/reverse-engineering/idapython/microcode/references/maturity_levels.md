# Microcode Maturity Levels (MMAT_*)

## Overview

Hex-Rays processes microcode through a pipeline of increasing maturity levels. At each level,
specific optimization passes run. Understanding when your optimizer is called and what the
microcode looks like at each level is essential for writing correct plugins.

## Level Details

### MMAT_ZERO (0)
- **State**: No microcode generated yet
- **When**: Before analysis begins
- **Notes**: You should never see this in an optimizer callback

### MMAT_GENERATED (1)
- **State**: Raw microcode, roughly 1:1 with native instructions
- **Characteristics**:
  - Every native instruction produces one or more micro-instructions
  - Many redundant operations (e.g., explicit flag updates)
  - Stack frame not yet analyzed
  - No optimizations applied
- **When to use**: `microcode_filter_t` operates here (replaces native → microcode translation)

### MMAT_PREOPTIMIZED (2)
- **State**: Basic peephole optimizations done
- **Characteristics**:
  - Dead flag computations removed
  - Some constant folding
  - Obvious no-ops eliminated
  - Stack variables beginning to be recognized
- **When to use**: Rarely targeted by plugins

### MMAT_LOCOPT (3)
- **State**: Local (per-block) optimization
- **Characteristics**:
  - Copy propagation within blocks
  - Common subexpression elimination (local)
  - Dead code elimination (local)
  - **This is where optblock_t and optinsn_t callbacks fire**
- **When to use**: **Most common level for deobfuscation plugins**
  - Indirect jump resolution (m_ijmp → m_goto)
  - Opaque predicate removal
  - Pattern-based simplifications
- **Important**: Your optimizer may be called multiple times per block if you return non-zero
  (indicating changes). The decompiler re-runs optimization passes until no more changes occur.

### MMAT_CALLS (4)
- **State**: Call analysis
- **Characteristics**:
  - Function call arguments identified
  - Return values tracked
  - Calling convention analysis
- **When to use**: Plugins that need to modify call semantics

### MMAT_GLBOPT1 (5)
- **State**: Global optimization phase 1
- **Characteristics**:
  - Cross-block copy propagation
  - Global dead code elimination
  - Some control flow simplification
- **When to use**: Plugins that need global context

### MMAT_GLBOPT2 (6)
- **State**: Global optimization phase 2
- **Characteristics**:
  - More aggressive optimizations
  - Type propagation beginning
- **When to use**: Rarely targeted directly

### MMAT_GLBOPT3 (7)
- **State**: Global optimization phase 3
- **Characteristics**:
  - Final optimization passes
  - Nearly ready for variable allocation
- **When to use**: Last chance for microcode modifications

### MMAT_LVARS (8)
- **State**: Local variable allocation
- **Characteristics**:
  - Micro-registers mapped to named local variables
  - Stack variables finalized
  - Types assigned
  - Ready for ctree generation
- **When to use**: Read-only analysis; modifications here are risky

## Maturity Check Pattern

```python
class MyOptimizer(ida_hexrays.optblock_t):
    def func(self, blk):
        mat = blk.mba.maturity

        # Only run at LOCOPT or above
        if mat < ida_hexrays.MMAT_LOCOPT:
            return 0

        # Optionally skip higher levels if not needed
        if mat > ida_hexrays.MMAT_LOCOPT:
            return 0  # Only optimize once

        # ... your optimization logic ...
        return 0
```

## Cross-Maturity Hazard: Different Results at Different Levels

**Critical**: The optimizer callback is invoked at **every** maturity level (MMAT_LOCOPT and above)
for the same block. Constant propagation can produce **different results** at different maturity
levels because the decompiler transforms the microcode between levels.

Example from real-world obfuscation:
- **MMAT_LOCOPT (3)**: Propagation resolves `m_ijmp` operand to `0x5644BA07` — a bogus value
  (decompiler hasn't fully simplified the microcode yet)
- **MMAT_LOCOPT+1 (4)**: Propagation resolves to `0x21158` — the correct target

**Consequence**: If your optimizer records state (like "already patched this address") at maturity 3
with the wrong result, the correct result at maturity 4 will be blocked. This is
**cross-maturity poisoning**.

**Prevention pattern**:
1. **Validate before recording**: Check that the resolved target is reasonable (e.g., within
   ±64KB of the function entry) before adding to any "already processed" set
2. **Defer marking**: Only add to `_patched_addrs` after validation passes, not before
3. **Don't assume first result is correct**: Lower maturity results may be wrong

```python
def _auto_patch(self, mba, target_addr, ijmp_ea):
    if ijmp_ea in self._patched_addrs:
        return False
    # Validate BEFORE marking
    MAX_DIST = 0x10000  # 64KB
    if abs(target_addr - mba.entry_ea) > MAX_DIST:
        return False  # bogus target — don't mark, let next maturity try
    # Only mark after validation
    self._patched_addrs.add(ijmp_ea)
    # ... proceed with patching ...
```

## Re-optimization Behavior

When `optblock_t.func()` returns a non-zero value:
1. The decompiler marks the block as needing re-optimization
2. Standard optimization passes re-run on the block
3. Your optimizer is called again
4. This repeats until your optimizer returns 0

**Pitfall**: If your optimizer always returns non-zero, it creates an infinite loop.
Always ensure your transformation is idempotent or guard against re-application:

```python
def func(self, blk):
    # Guard: only transform if m_ijmp exists
    if blk.tail and blk.tail.opcode == ida_hexrays.m_ijmp:
        # After replacing with m_goto, this check will fail
        # on the next invocation → no infinite loop
        ...
        return 1
    return 0
```

## Monitoring Maturity Changes

Use `Hexrays_Hooks.maturity` to observe level transitions:

```python
class MaturityLogger(ida_hexrays.Hexrays_Hooks):
    def maturity(self, cfunc, new_maturity):
        NAMES = {0:"ZERO", 1:"GENERATED", 2:"PREOPTIMIZED",
                 3:"LOCOPT", 4:"CALLS", 5:"GLBOPT1",
                 6:"GLBOPT2", 7:"GLBOPT3", 8:"LVARS"}
        print(f"[maturity] {cfunc.entry_ea:#x} → {NAMES.get(new_maturity, '?')}")
        return 0
```
