# Swift String/Xref Repair

Use this workflow for Swift binaries when strings are visible in `__cstring` but cross-references are missing or incomplete.

## Trigger Conditions

- Swift artifacts exist (`_$s...`, `__swift5_*`, Swift runtime metadata).
- `find_regex` finds expected strings but `xrefs_to` is empty or clearly incomplete.
- Decompiler shows API loading via `&unk_xxx` static containers instead of direct string refs.

## Objectives

- Recover where static strings are consumed.
- Make references queryable in IDA/MCP tools.
- Keep synthetic fixes explicit and auditable.

## Playbook

1. Confirm the mismatch.
- Locate candidate strings with `find_regex`.
- Validate missing refs with `xrefs_to`.

2. Find loader logic and static containers.
- Start from setup/init functions with `decompile` and `disasm`.
- Follow data refs from code to static tables with `find` and `xrefs_to`.

3. Recover structure conservatively.
- Prefer a minimal entry type before deep runtime decoding.

```c
typedef struct {
    const char *ptr;
    unsigned long long meta;
} SwiftStaticStringRef;
```

Common variant (often seen in Swift static object tables):

```c
typedef struct {
    unsigned long long tagged_len;
    const char *base_ptr;  // actual cstring may be at base_ptr + 0x20
} SwiftStaticStringRefV2;
```

- Apply to table-like `unk_` blocks, then rename and comment.

4. Repair analyst-facing references.
- Add user data refs from code EAs to concrete string EAs.
- Prefer code source EAs, not pure data-field EAs.
- Mark synthetic refs as analyst-added.

5. Validate and document.
- Re-run `xrefs_to` for repaired strings.
- Confirm each repaired string has meaningful code-side refs.
- Keep comments/script output so the repair is reproducible.

## Scripted Helper

Use `scripts/swift_string_xref_repair.py` through `py_eval`.

Default behavior (no hardcoded addresses):
- discovery root: current cursor function.
- auto-detect candidate static string tables from code->data refs.
- patch only missing code->string refs by default.
- supports common entry layouts (`ptr`, `tagged_len+ptr`, and `+0x20` string base).
- scans a few header slots before the first entry (to handle static object headers).
- tolerates tagged/high-bit pointer encodings seen in some Swift static tables.
- can optionally apply `SwiftArrayStringTemplateN` types to table headers.
- can optionally add template->cstring USER refs (with item-head fallback) and table/entry/string comments.

Example override:

```python
config = {
    "function": None,  # current cursor function (or use an explicit function EA like "0x<func_ea>")
    "dry_run": True,
    "annotate_templates": True,
    "annotate_table_links": True,
    "table_link_source": "auto",  # auto/ptr_field/entry/table_header/table_base/table_code_src
    "annotate_table_comments": True,
    "annotate_string_comments": True,
    "annotate_code_ref_comments": True,
    "strides": [16, 24],
    "table_addrs": [],
    "header_scan_steps": 4,
    "max_back_steps": 0,
}
result = run(config)
```

Notes:
- The snippet above is not hardcoded behavior; it is only an override example.
- `function=False` disables function-root discovery and uses only `table_addrs`.
- Prefer function address or `None` over demangled names when symbol quality is poor.
- Keep `max_back_steps=0` by default to avoid merging adjacent static objects.
- With `annotate_templates=True`, the script will declare/apply:
  `SwiftArrayStringTemplate2`, `SwiftArrayStringTemplate3`, `SwiftArrayStringTemplate4`
  when header shape matches `{reserved0,reserved1,count,capacity}`.
- With `annotate_table_links=True`, the script adds analyst USER refs from template
  entries to concrete cstring EAs; in `auto` mode it falls back to item head /
  template header / table base / code source when interior field EAs cannot carry xrefs.
- With `annotate_table_comments=True`, the script writes summary comment on table base
  and per-entry comments with decoded target strings.
- Per-entry comments are written to the concrete `__data` entry/pointer member
  addresses (`entry_ea` / `ptr_field_ea`) so the `items.*` lines are directly annotated.
  The script writes these as anterior/extra comments (line-above style) and clears
  stale inline comments to avoid struct item-head comment collapsing noise.
- Table summary comments are also written as multi-line anterior/extra comments
  (summary + entry previews), so long Swift paths are easier to read in `__data`.
- With `annotate_string_comments=True`, the script writes reverse trace comments on
  each repaired cstring (table+index+layout), which helps when xref UI is sparse.
- With `annotate_code_ref_comments=True`, the script writes summary comments on code
  xref source EAs (for example in `loadAPIs`) so you can see referenced string groups
  directly at call-site level.
- Code-site comments are written as multi-line anterior/extra comments (line-above
  style), so long previews do not clutter inline disassembly comments.

## Fallback When `py_eval` Is Unavailable

If unsafe tools are disabled, still complete:
- structure application,
- rename/comment/type recovery,
- explicit note on unresolved xref limitations.

## Quality Rules

- Do not present synthetic refs as compiler-generated.
- Keep all added refs reproducible (scriptable or clearly documented).
- Use generic names (`SwiftStaticStringRef`, `SwiftStaticStringTableN`) unless semantics are proven.
- Keep sample-specific addresses out of shared skill docs/scripts.
