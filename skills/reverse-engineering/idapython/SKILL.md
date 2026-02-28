---
name: idapython
description: IDA Pro Python scripting and plugin development. Use when writing IDAPython scripts, developing plugins, analyzing binaries, working with IDA's API for disassembly, decompilation (Hex-Rays), type systems, cross-references, functions, segments, or any IDA database manipulation. Covers ida_* modules (50+), idautils iterators, common patterns, plugin architecture, API safety rules, and Hex-Rays microcode API (via microcode/ sub-skill). Also trigger on optblock_t, minsn_t, mop_t, mba_t, microcode optimization, or deobfuscation plugin development.
---

# IDAPython

Use modern `ida_*` modules. Avoid legacy `idc` module.

## Module Router

| Task | Module | Key Items |
|------|--------|-----------|
| Bytes/memory | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_flags`, `create_*` |
| Functions | `ida_funcs` | `func_t`, `get_func`, `add_func`, `get_func_name` |
| Names | `ida_name` | `set_name`, `get_name`, `demangle_name` |
| Types | `ida_typeinf` | `tinfo_t`, `apply_tinfo`, `parse_decl` |
| Decompiler | `ida_hexrays` | `decompile`, `cfunc_t`, `lvar_t`, ctree visitor |
| Segments | `ida_segment` | `segment_t`, `getseg`, `add_segm` |
| Xrefs | `ida_xref` | `xrefblk_t`, `add_cref`, `add_dref` |
| Instructions | `ida_ua` | `insn_t`, `op_t`, `decode_insn` |
| Stack frames | `ida_frame` | `get_frame`, `define_stkvar` |
| Iteration | `idautils` | `Functions()`, `Heads()`, `XrefsTo()`, `Strings()` |
| UI/dialogs | `ida_kernwin` | `msg`, `ask_*`, `jumpto`, `Choose` |
| Database info | `ida_ida` | `inf_get_*`, `inf_is_64bit()` |
| Analysis | `ida_auto` | `auto_wait`, `plan_and_wait` |
| Flow graphs | `ida_gdl` | `FlowChart`, `BasicBlock` |
| Register tracking | `ida_regfinder` | `find_reg_value`, `reg_value_info_t` |
| Instruction metadata | `ida_idp` | `is_ret_insn()`, `is_call_insn()`, `is_indirect_jump_insn()` |
| Instruction IDs | `ida_allins` | `NN_*` (x86), `ARM_*` (ARM), `MIPS_*` (MIPS) |
| Structures & enums | `ida_struct`, `ida_enum` | struct/enum creation and editing |
| Comments | `ida_bytes` / `idc` | `set_cmt()`, `get_cmt()` |

## Core Patterns

### Iterate functions
```python
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    func = ida_funcs.get_func(ea)
```

### Iterate instructions in function
```python
for head in idautils.FuncItems(func_ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, head):
        print(f"{head:#x}: {insn.itype}")
```

### Cross-references
```python
for xref in idautils.XrefsTo(ea):
    print(f"{xref.frm:#x} -> {xref.to:#x} type={xref.type}")
```

### Read/write bytes
```python
data = ida_bytes.get_bytes(ea, size)
ida_bytes.patch_bytes(ea, b"\x90\x90")
```

### Names
```python
name = ida_name.get_name(ea)
ida_name.set_name(ea, "new_name", ida_name.SN_NOCHECK)
```

### Decompile function
```python
cfunc = ida_hexrays.decompile(ea)
if cfunc:
    print(cfunc)  # pseudocode
    for lvar in cfunc.lvars:
        print(f"{lvar.name}: {lvar.type()}")
```

### Walk ctree (decompiled AST)
```python
class MyVisitor(ida_hexrays.ctree_visitor_t):
    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            print(f"Call at {e.ea:#x}")
        return 0

cfunc = ida_hexrays.decompile(ea)
MyVisitor().apply_to(cfunc.body, None)
```

### Apply type
```python
tif = ida_typeinf.tinfo_t()
if ida_typeinf.parse_decl(tif, None, "int (*)(char *, int)", 0):
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
```

### Create structure
```python
udt = ida_typeinf.udt_type_data_t()
m = ida_typeinf.udm_t()
m.name = "field1"
m.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
m.offset = 0
m.size = 4
udt.push_back(m)
tif = ida_typeinf.tinfo_t()
tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
tif.set_named_type(ida_typeinf.get_idati(), "MyStruct")
```

### Strings list
```python
for s in idautils.Strings():
    print(f"{s.ea:#x}: {str(s)}")
```

### Wait for analysis
```python
ida_auto.auto_wait()  # Block until autoanalysis completes
```

## Key Constants

| Constant | Value/Use |
|----------|-----------|
| `BADADDR` | Invalid address sentinel |
| `ida_name.SN_NOCHECK` | Skip name validation |
| `ida_typeinf.TINFO_DEFINITE` | Force type application |
| `o_reg`, `o_mem`, `o_imm`, `o_displ`, `o_near` | Operand types |
| `dt_byte`, `dt_word`, `dt_dword`, `dt_qword` | Data types |
| `fl_CF`, `fl_CN`, `fl_JF`, `fl_JN`, `fl_F` | Code xref types |
| `dr_R`, `dr_W`, `dr_O` | Data xref types |

## Critical Rules

1. **NEVER convert hex/decimal manually** — use `int_convert` MCP tool
2. **Wait for analysis**: Call `ida_auto.auto_wait()` before reading results
3. **Thread safety**: IDA SDK calls must run on main thread (use `@idasync`)
4. **64-bit addresses**: Always assume `ea_t` can be 64-bit

## Anti-Patterns

| Avoid | Do Instead |
|-------|------------|
| `idc.*` functions | Use `ida_*` modules |
| Hardcoded addresses | Use names, patterns, or xrefs |
| Manual hex conversion | Use `int_convert` tool |
| Blocking main thread | Use `execute_sync()` for long ops |
| Guessing at types | Derive from disassembly/decompilation |

## Plugin Architecture

IDA plugins follow one of these patterns:

### 1. Classic `plugin_t`

```python
import ida_idaapi
import ida_kernwin

class MyPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP   # or PLUGIN_UNL for one-shot
    comment = "My Plugin"
    help = ""
    wanted_name = "My Plugin"
    wanted_hotkey = "Ctrl-Shift-M"

    def init(self):
        # Called once when IDA loads the plugin
        # Return PLUGIN_OK, PLUGIN_SKIP, or PLUGIN_KEEP
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Called when user activates the plugin
        pass

    def term(self):
        # Called when IDA unloads the plugin
        pass

def PLUGIN_ENTRY():
    return MyPlugin()
```

### 2. Action Handler (preferred for menu/toolbar integration)

```python
class MyHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        # Perform the action
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# Register and attach to menu
ida_kernwin.register_action(ida_kernwin.action_desc_t(
    "my:action", "My Action", MyHandler(), "Ctrl-Shift-M"))
ida_kernwin.attach_action_to_menu("Edit/Plugins/", "my:action", 0)
```

### 3. Hex-Rays Callbacks

For decompiler plugins, register callbacks via `optblock_t`, `optinsn_t`, or `Hexrays_Hooks`:

```python
class MyOptimizer(ida_hexrays.optblock_t):
    def func(self, blk):
        # Called for each basic block during optimization
        # Return non-zero if changes were made
        return 0

opt = MyOptimizer()
opt.install()  # Register
# opt.remove()  # Unregister
```

For detailed microcode API documentation, read `microcode/SKILL.md`.

## Critical Safety Rules

### Thread Safety in Callbacks

IDA's internal locking means certain APIs are unsafe in certain contexts:

| API | optblock_t callback | timer callback (post-analysis) |
|-----|--------------------|------|
| `patch_byte/dword` | Safe | Deadlock risk (QReadWriteLock) |
| `del_items` | INTERR 50863 | Safe |
| `create_insn` | INTERR 50863 | Safe |
| `add_func` / `del_func` | INTERR 50863 | Safe |
| `set_cmt` | May be cleared by later del_items | Safe after func rebuild |

**Pattern**: Do binary patching (`patch_byte`) inside optimizer callbacks. Defer IDB modifications
(`del_items`, `create_insn`, `add_func`) to a timer:

```python
def _deferred_work():
    ida_bytes.del_items(ea, 0, size)
    ida_ua.create_insn(ea)
    ida_funcs.add_func(start, end)
    return -1  # one-shot timer

ida_kernwin.register_timer(100, _deferred_work)
```

### Cooperative Timeout for Batch Decompilation

`ida_hexrays.decompile()` has no timeout parameter. For batch operations (`fix_all`), implement
cooperative timeout in `optblock_t.func()`:
- Set `_deadline = time.time() + TIMEOUT` before each `decompile()` call
- Check in `func()` with `_timed_out` short-circuit (zero `time.time()` overhead after timeout)
- Check in propagation loops every ~16 instructions

See `references/api_safety.md` → "Cooperative Timeout" for the full pattern.

### Cross-Maturity Safety

The optimizer callback fires at multiple maturity levels. Constant propagation may give **wrong
results at lower maturity** and correct results at higher maturity. Never mark an address as
"processed" before validating the result (e.g., ±64KB distance check). See
`microcode/references/maturity_levels.md` → "Cross-Maturity Hazard".

### Architecture Detection

Always detect architecture at runtime rather than hardcoding:

```python
import ida_ida
info = ida_ida.inf_get_procname()  # "ARM" or "metapc" (x86)
is_arm = "ARM" in info
is_x64 = not is_arm
```

### Instruction Decoding Best Practices

Prefer `ida_ua.decode_insn()` + `ida_allins` constants over raw byte matching:

```python
import ida_ua, ida_allins, ida_idp

insn = ida_ua.insn_t()
length = ida_ua.decode_insn(insn, ea)
if length > 0:
    # Architecture-independent checks
    if ida_idp.is_ret_insn(insn):
        pass  # It's a return instruction
    if ida_idp.is_call_insn(insn):
        pass  # It's a call instruction

    # Architecture-specific via ida_allins
    if insn.itype == ida_allins.NN_cmp:    # x86 CMP
        pass
    if insn.itype == ida_allins.ARM_stp:   # ARM64 STP
        pass
```

## Using IDA MCP

When an IDA instance is connected via MCP, prefer MCP tools for interactive analysis:

- `decompile` / `disasm` — View pseudocode or assembly
- `lookup_funcs` / `list_funcs` — Find functions by name or address
- `xrefs_to` — Cross-references
- `find` / `find_regex` — Search strings, immediates, references
- `rename` / `set_comments` — Annotate the database
- `set_type` / `declare_type` — Apply or create types

**Important**: When multiple IDA instances are open, always use the `_instance` parameter to
target the correct one. NEVER switch the active instance — it disrupts the user's workflow.

## Sub-Skills

- **`microcode/SKILL.md`** — Hex-Rays microcode API deep-dive: `mba_t`, `mblock_t`, `minsn_t`, `mop_t`, writing `optblock_t`/`optinsn_t` optimizers, `microcode_filter_t`, all mcode opcodes. Read this when working with decompiler internals, deobfuscation plugins, or constant propagation.

## Reference Files

- **`references/api_safety.md`** — API threading/safety constraints: which APIs are safe in optimizer callbacks vs timer callbacks, deferred execution patterns, batch fixup queues.
- **`references/ida_allins_common.md`** — Common `ida_allins` instruction constants for x86/ARM64.
- **`microcode/references/constant_propagation.md`** — Complete PropState engine implementation for cross-block constant propagation.
- **`microcode/references/deobfuscation_patterns.md`** — Obfuscation pattern catalog (computed jumps, opaque predicates, junk code, control flow flattening) and their microcode solutions.
- **`microcode/references/maturity_levels.md`** — What happens at each MMAT_* level and what to expect.
- **`microcode/references/mcode_opcodes.md`** — Complete mcode_t opcode table with encoding details.

## Detailed API Reference

For comprehensive documentation on any module, read `docs/<module>.md`:
- **High-use**: `ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_typeinf`, `ida_name`, `idautils`
- **Medium-use**: `ida_segment`, `ida_xref`, `ida_ua`, `ida_frame`, `ida_kernwin`
- **Specialized**: `ida_dbg` (debugger), `ida_nalt` (netnode storage), `ida_regfinder` (register tracking)

Full RST sources from hex-rays.com available at `docs/<module>.rst`.
