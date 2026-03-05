# IDA API Safety & Threading Constraints

## Optimizer Callback Context (optblock_t.func / optinsn_t.func)

These callbacks run inside the Hex-Rays decompiler's analysis pipeline. The IDB is partially locked.

### Safe Operations
- `ida_bytes.patch_byte()`, `patch_word()`, `patch_dword()` — Binary patching is safe
- `ida_bytes.get_bytes()`, `get_byte()`, `get_dword()` — Reading memory is always safe
- `ida_ua.decode_insn()` — Decoding instructions from raw bytes is safe
- Microcode manipulation (modifying `minsn_t`, `mop_t`, inserting/removing instructions)
- `mblock_t.make_nop(insn)` — NOP a microcode instruction (marks lists dirty)
- `minsn_t._make_nop()` — NOP without marking lists dirty
- Accessing `mba_t`, `mblock_t` properties and iterators

### Unsafe Operations (cause INTERR 50863 or deadlock)
- `ida_bytes.del_items()` — INTERR 50863
- `ida_ua.create_insn()` — INTERR 50863
- `ida_funcs.add_func()` / `del_func()` — INTERR 50863
- `ida_auto.auto_wait()` — Deadlock
- Any API that triggers auto-analysis internally

### Deferred Execution Pattern

Use `ida_kernwin.register_timer()` to defer unsafe operations.

#### Simple: One-Shot Timer (single fixup)

```python
class _DeferredFixup:
    def __init__(self, ea, size, func_start, func_end):
        self.ea = ea
        self.size = size
        self.func_start = func_start
        self.func_end = func_end

    def __call__(self):
        # Now safe to modify IDB
        ida_bytes.del_items(self.ea, 0, self.size)
        for addr in range(self.ea, self.ea + self.size, alignment):
            ida_ua.create_insn(addr)
        ida_funcs.del_func(self.func_start)
        ida_funcs.add_func(self.func_start, self.func_end)
        # Comments must be set AFTER func rebuild
        ida_bytes.set_cmt(self.ea, "patched", False)
        return -1  # -1 = one-shot timer

ida_kernwin.register_timer(100, _DeferredFixup(ea, size, start, end))
```

The 100ms delay ensures the decompiler has fully released its locks.

#### Better: Batch Fixup Queue (many fixups)

When an optimizer patches dozens of sites per decompilation pass, spawning one
timer per fixup causes a "timer storm" — hundreds of overlapping timers that
fight over IDB locks. Use a **module-level batch queue** with a single timer:

```python
_g_fixup_queue = []     # list of (ea, size, func_start, func_end)
_g_fixup_timer = [None] # single shared timer handle

def _schedule_fixup(ea, size, func_start, func_end):
    """Enqueue a fixup; start the batch timer if not already running."""
    _g_fixup_queue.append((ea, size, func_start, func_end))
    if _g_fixup_timer[0] is None:
        _g_fixup_timer[0] = ida_kernwin.register_timer(100, _run_fixup_batch)

def _run_fixup_batch():
    """Drain the entire queue in one callback, then stop the timer."""
    batch = list(_g_fixup_queue)
    _g_fixup_queue.clear()
    _g_fixup_timer[0] = None

    for ea, size, func_start, func_end in batch:
        ida_bytes.del_items(ea, 0, size)
        for addr in range(ea, ea + size, alignment):
            ida_ua.create_insn(addr)
        ida_funcs.del_func(func_start)
        ida_funcs.add_func(func_start, func_end)
        ida_bytes.set_cmt(ea, "patched", False)

    return -1  # -1 = one-shot (self-cancels)
```

Key properties:
- At most **one** active timer at any time — no timer storms
- Fixups accumulated across multiple `optblock_t.func()` invocations are
  batched into a single IDB modification pass
- `auto_wait()` is **never** called — IDA auto-analysis runs asynchronously
  after the batch completes

#### Zero `auto_wait` Strategy

**Never call `auto_wait()` anywhere** — not inside callbacks (deadlock), not
inside deferred timers (blocks UI), not between batches. Let IDA's background
auto-analysis proceed asynchronously. If you need convergence, run a second
decompilation pass after the auto-analysis settles naturally.

## Hexrays_Hooks Context

`Hexrays_Hooks` event callbacks have varying safety levels:

| Event | When | Safety |
|-------|------|--------|
| `flowchart` | Before microcode generation | Read-only IDB access |
| `microcode` | After microcode generation | Can modify microcode |
| `locopt` | During local optimization | Same as optblock_t |
| `glbopt` | During global optimization | Similar constraints |
| `maturity` | When maturity level changes | Read microcode only |

## Cooperative Timeout for Optimizer Callbacks

`ida_hexrays.decompile()` is a synchronous C call with **no timeout parameter**. If your
optimizer callback (`optblock_t.func`) does expensive work (e.g., constant propagation over
many predecessor blocks), a single function can block IDA for minutes.

**Solution**: Cooperative timeout — the caller sets a deadline before `decompile()`, and the
callback checks it periodically:

```python
class MyOptimizer(ida_hexrays.optblock_t):
    DECOMPILE_TIMEOUT = 3.0  # seconds per function

    def __init__(self):
        super().__init__()
        self._deadline = 0      # set by caller before decompile()
        self._timed_out = False  # set when deadline exceeded
        self._func_calls = 0    # callback invocation count

    def func(self, blk):
        self._func_calls += 1
        # Fast path: already timed out, skip everything (no time.time() call)
        if self._timed_out:
            return 0
        # Check deadline
        if self._deadline and time.time() > self._deadline:
            self._timed_out = True
            return 0
        return self._func_impl(blk)
```

**Caller side** (e.g., `fix_all()`):
```python
optimizer._timed_out = False
optimizer._func_calls = 0
optimizer._deadline = time.time() + optimizer.DECOMPILE_TIMEOUT
try:
    ida_hexrays.decompile(ea)
finally:
    optimizer._deadline = 0
```

**Key details**:
- The `_timed_out` short-circuit avoids `time.time()` calls after timeout — critical because
  the decompiler continues calling `func()` thousands of times even after it returns 0
- Inside `_propagate()`, check deadline every ~16 instructions (not every instruction — too
  much overhead; not every 64 — microcode blocks often have fewer instructions)
- This is a **defensive layer**, not the primary fix. Always fix root causes (e.g., validate
  targets before expensive operations) rather than relying on timeout alone

## General Rules

1. **Never call `auto_wait()` — anywhere** — deadlock in callbacks, UI-blocking in timers.
   Use the zero-`auto_wait` strategy: let auto-analysis run asynchronously
2. **Prefer batch fixup queue over per-fixup timers** — avoids timer storms
3. **Prefer `mblock_t.make_nop(insn)` over manual NOP** — it correctly marks lists dirty
4. **After modifying microcode, call `mba.verify(True)`** in debug builds to catch issues
5. **Use `instance_id` parameter with MCP** — prefer passing it directly over calling `instance_switch`
6. **`set_cmt()` placed before `del_items()` will be lost** — always set comments last
7. **Use `DELIT_SIMPLE` flag with `del_items()`** — the default `flag=0` may not fully clear
   IDB item markers, causing subsequent `create_insn()` to fail with length 0. Always use
   `ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)` for reliable cleanup
8. **Function rebuild wipes previously defined code** — after `del_func` + `del_items` +
   `add_func`, any code items you defined earlier at JUMPOUT targets will be gone. Re-define
   them _after_ the function rebuild, not before
9. **Always pass `encoding="utf-8"` to `open()`** when loading scripts via `py_eval` —
   `open()` defaults to the system locale (e.g. `cp1252` on Windows), which causes
   `UnicodeDecodeError` on files containing non-ASCII characters such as em-dashes or
   Unicode comments. Use `exec(open(path, encoding="utf-8").read())`
