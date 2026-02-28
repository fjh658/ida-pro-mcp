# Computed-Branch Deobfuscation

Use this workflow when decompilation produces `JUMPOUT(...)` or broken control flow due to computed indirect jumps (`JMP reg` on x86_64, `BR Xn` on ARM64).

## Trigger Conditions

- Decompiled pseudocode contains `JUMPOUT(...)` calls.
- Disassembly shows indirect jumps (`jmp rax`, `BR X8`, etc.) preceded by arithmetic sequences computing the target.
- Functions have abnormally small boundaries (prologue only, real body is outside).
- Junk bytes or opaque predicates (complementary conditional jump pairs) appear between basic blocks.
- Binary uses computed-branch obfuscation (e.g. register-indirect jumps with constant folding patterns).

## Obfuscation Pattern

1. A constant is written to a stack variable (e.g., `MOV W8, #0xF5; STR W8, [SP+var_28]`).
2. Arithmetic operations (XOR, ADD, SUB, sign-extend, etc.) compute the real target address.
3. An indirect jump (`JMP reg` / `BR Xn`) transfers control to the computed target.
4. Junk bytes fill the gap between the indirect jump and the real target.
5. Opaque predicates (complementary conditional jumps, always taking one path) may guard the real target.

IDA cannot statically resolve the indirect jump target, resulting in `JUMPOUT` or incorrect function boundaries.

## Automated Fix: `computed_branch_deobf.py`

The built-in script resolves computed branches at the Hex-Rays microcode level via constant propagation.

### Install / Uninstall

```bash
python3 computed_branch_deobf.py --install          # copy to ~/.idapro/plugins/
python3 computed_branch_deobf.py --install --force   # overwrite existing
python3 computed_branch_deobf.py --uninstall         # remove from plugins dir
python3 computed_branch_deobf.py --version           # show version
```

### Quick Usage

**Via IDA Script File** (manual):
File → Script File → select `computed_branch_deobf.py`.

**Via MCP `py_eval`** (automated):
Read the script content first, then pass it to `py_eval`:
```python
exec(open("/path/to/computed_branch_deobf.py", encoding="utf-8").read())
```
Replace `/path/to/` with the actual script location on the IDA host.
Always pass `encoding="utf-8"` — `open()` defaults to the system locale, which may not be UTF-8
(especially on Windows), causing `UnicodeDecodeError` on files with non-ASCII characters.

This will:
1. Install a Hex-Rays `optblock_t` optimizer that intercepts `m_ijmp` instructions.
2. Perform constant propagation to resolve each indirect jump target.
3. Validate targets (64KB distance check) and patch the binary: replace indirect jumps with direct jumps, NOP junk bytes and opaque predicates.
4. Rebuild function boundaries via deferred fixups (timer-based, zero `auto_wait`).
5. Batch-decompile all functions with a progress dialog (cancellable, 3s per-function timeout).

### What It Does (Six Phases)

Fix All (`cb_deobf_fix_all()`) runs six phases in sequence, each convergent (repeats until no more changes):

**Phase 1 — Microcode Analysis** (inside optimizer callback):
- Detects `m_ijmp` at block tail.
- Multi-level BFS predecessor traversal (depth limit 16) for constant propagation.
- Tracks micro-registers, stack variables, and stack-address registers.
- Cooperative timeout: `DECOMPILE_TIMEOUT` (default 3s) per function; `_propagate()` checks deadline every 16 instructions. `func()` callback short-circuits when timed out (zero `time.time()` overhead).
- Replaces resolved `m_ijmp` with `m_goto`.

**Phase 2 — Binary Patching** (inside optimizer callback):
- Distance validation: target must be within ±64KB of function entry (`MAX_PATCH_DIST`); bogus targets from low-maturity propagation are rejected. `_patched_addrs` marking deferred until after validation to prevent cross-maturity poisoning.
- Patches indirect jump → direct jump (`E9 rel32` / `B imm26`).
- NOPs junk bytes between jump and target.
- NOPs opaque predicates (complementary conditional jump pairs).
- Fixes ARM64 literal pool loads pointing into NOP regions.
- Cleans dead computation chains whose literal-pool loads were NOP'd.

**Phase 3 — Deferred IDB Fixups** (timer callback, batch queue):
- `del_items(DELIT_SIMPLE)` + `create_insn` to convert NOP bytes to instructions.
- `del_func` + `add_func` to rebuild function boundaries.
- Repairs adjacent functions disrupted by boundary changes.
- Adds `[deobf]` comments at all patched locations.

**Phase 3.5 — Residual Fix Loop** (`_extend_tiny_prologue_funcs`):
- Scans all functions smaller than 0x40 bytes that decompile with JUMPOUT.
- Extends boundaries by scanning forward for the real function end (RET or next prologue).
- Absorbs adjacent functions when a JUMPOUT target from the tiny function lands inside the adjacent function body (JUMPOUT-target-based heuristic — more precise than xref-based).
- Re-decompiles all functions after extension to catch newly-exposed computed branches.
- Up to 5 convergence passes.

**Phase 4 — Standalone Opaque Predicate Cleaning** (`_clean_standalone_opaque_preds`):
- Scans every function for complementary Jcc pairs (opaque predicates) that Phase 2 missed — these are standalone obfuscation constructs not guarding a computed branch.
- NOPs junk bytes between the complementary pair and the real target.
- Rebuilds IDB items (`del_items` + `create_insn` + `del_func`/`add_func`).
- Re-decompiles affected functions; newly-visible code may contain computed branches the optimizer can now resolve.
- Up to 3 convergence passes.

**Phase 5 — Boundary Repair** (`_repair_jumpout_boundaries`):
- Final sweep: decompiles all functions and parses JUMPOUT targets from pseudocode.
- For targets at/past function end not inside another function: extends boundary via `_scan_for_func_end`.
- For targets inside an adjacent function: absorbs the adjacent function if its only inbound xrefs come from the current function.
- Up to 3 convergence passes.

### Residual JUMPOUT Categories

After all six phases, remaining JUMPOUTs fall into these categories:

| Category | Description | Example |
|----------|-------------|---------|
| IN_FUNC | Target inside function boundary but optimizer can't resolve | Bogus propagation picking up NOP bytes as constants |
| OUT_FUNC | Target outside function, boundary repair extends it | Handled by Phase 5 |
| BEFORE | Target before function start (bogus) | Propagation produces nonsense address |
| SHORT_JMP | x86 `jmp reg` is 3 bytes, can't fit `E9 rel32` (5 bytes) | Need trampoline or microcode-only fix |

### Manual Residual Fix Strategies

When automatic phases fail, these manual strategies resolve remaining JUMPOUTs:

| Strategy | When to Use |
|----------|-------------|
| Define undefined code bytes | Target address has raw bytes, not instructions |
| Extend function boundary | Function ends before its actual RET |
| Patch indirect → direct jump | `jmp reg` can be overwritten with `E9 rel32` + NOP |
| Convert tail-call `jmp` → `call` | `E9` → `E8` single byte fix for cross-function jumps |
| Create missing target function | Tail-call target has prologue but no function entry |
| Split mis-merged functions | ARM64 function incorrectly merged with adjacent code |

### Key API Safety Rules

| API | optblock_t callback | timer callback |
|-----|--------------------|-----------------------------|
| `patch_byte` | Safe | Deadlock risk |
| `del_items` / `create_insn` | INTERR 50863 | Safe |
| `add_func` / `del_func` | INTERR 50863 | Safe |
| `auto_wait` | Blocks UI | Blocks UI (removed) |

For detailed API safety constraints, see `../../idapython/references/api_safety.md`.

## IDAPython Sub-Skills

When deeper microcode work is needed (custom propagation, new opcode support, etc.):

- **`../../idapython/SKILL.md`** — IDAPython module map, plugin architecture, safety rules.
- **`../../idapython/microcode/SKILL.md`** — Hex-Rays microcode API deep-dive (`mba_t`, `mblock_t`, `minsn_t`, `mop_t`, optimizer patterns).
- **`../../idapython/microcode/references/constant_propagation.md`** — Complete PropState engine reference.
- **`../../idapython/microcode/references/deobfuscation_patterns.md`** — Obfuscation pattern catalog and microcode solutions.

## Fallback When `py_eval` Is Unavailable

If unsafe tools are disabled:
1. Use `decompile` to identify JUMPOUT functions.
2. Use `disasm` to trace the arithmetic chain manually.
3. Use `find_bytes` to locate indirect jump patterns (`FF E0`–`FF E7` for x86, `D6 1F 00 20` for ARM64 RET vs `D6 3F 0?` for BR).
4. Document findings and recommend running the script in an unsafe-enabled session.

## Tested Results

| Binary | Arch | Functions | Before | After | Remaining |
|--------|------|-----------|--------|-------|-----------|
| MyDemo | ARM64 | ~550 | ~170 JUMPOUT | **0 JUMPOUT** | — |
| MyDemo | x86_64 | ~490 | ~37 JUMPOUT | **8 JUMPOUT** | Bogus propagation + short-jmp limitation |

ARM64 achieves 100% resolution. x86_64 residuals are hard cases requiring enhanced propagation (NOP-byte filtering) or trampoline-based patching for 3-byte `jmp reg` instructions.

## Quality Rules

- Always verify with `decompile` after the script runs — zero JUMPOUT is the target.
- The script is idempotent (`_patched_addrs` prevents double-patching; marked only after distance validation).
- Fix All completes in ~10 seconds for ~490 functions; slow functions auto-skipped via cooperative timeout.
- Keep sample-specific addresses out of shared docs/scripts.
- Document any manual residual fixes for reproducibility.
