"""Generic Swift static-string xref repair helper for IDA.

Designed for py_eval usage. It does not require hardcoded addresses.
Default behavior:
- uses current cursor function as discovery root
- detects candidate static string tables from data refs in that function
- supports common Swift table layouts (direct ptr and tagged-len + base ptr)
- adds user data xrefs from code EAs to string EAs only when missing
"""

import idc
import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_xref
import idautils
import textwrap

BAD = idc.BADADDR


def _is_64bit():
    """Handle IDA API differences across versions."""
    try:
        if hasattr(idaapi, "inf_is_64bit"):
            return bool(idaapi.inf_is_64bit())
    except Exception:
        pass

    try:
        inf = idaapi.get_inf_structure()
        if inf is not None:
            return bool(inf.is_64bit())
    except Exception:
        pass

    try:
        import ida_ida  # type: ignore

        if hasattr(ida_ida, "inf_is_64bit"):
            return bool(ida_ida.inf_is_64bit())
    except Exception:
        pass

    # Conservative fallback for modern macOS Swift targets.
    return True


PTR_SZ = 8 if _is_64bit() else 4

# Candidate entry decoders:
# (ptr_offset_in_entry, cstring_offset_from_ptr, layout_name)
ENTRY_CANDIDATES = [
    (0, 0, "ptr"),
    (PTR_SZ, 0x20, "tagged_len_ptr_plus_0x20"),
    (PTR_SZ, 0, "tagged_len_ptr"),
    (0, 0x20, "ptr_plus_0x20"),
]


def _ea(v):
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 0)
    except Exception:
        ea = idc.get_name_ea_simple(s)
        if ea != BAD:
            return ea
    raise ValueError(f"invalid ea or name: {v}")


def _is_loaded(ea):
    return ea != BAD and ida_bytes.is_loaded(ea)


def _read_ptr(ea):
    if not _is_loaded(ea):
        return BAD
    raw = ida_bytes.get_qword(ea) if PTR_SZ == 8 else ida_bytes.get_dword(ea)
    if PTR_SZ != 8:
        return raw

    # Swift static tables on macOS can carry tagged/high-bit pointers.
    # Try common untaggings and keep the first loaded candidate.
    cands = [raw, raw & 0x00FFFFFFFFFFFFFF, raw & 0x7FFFFFFFFFFFFFFF, raw & 0x0000FFFFFFFFFFFF]
    seen = set()
    for p in cands:
        if p in seen:
            continue
        seen.add(p)
        if _is_loaded(p):
            return p
    return raw


def _read_cstr(ea):
    if not _is_loaded(ea):
        return None
    b = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
    if not b:
        return None
    if isinstance(b, bytes):
        try:
            return b.decode("utf-8")
        except Exception:
            return b.decode("latin-1", errors="ignore")
    return str(b)


def _printable_ratio(s):
    if not s:
        return 0.0
    good = 0
    for ch in s:
        c = ord(ch)
        if 32 <= c < 127 or ch in "\t\r\n":
            good += 1
    return good / float(len(s))


def _try_entry_candidate(ea, ptr_off, str_off, min_strlen, layout):
    ptr_field_ea = ea + ptr_off
    raw_ptr = ida_bytes.get_qword(ptr_field_ea) if PTR_SZ == 8 else ida_bytes.get_dword(ptr_field_ea)
    ptr = _read_ptr(ptr_field_ea)
    if not _is_loaded(ptr):
        return None

    str_ea = ptr + str_off
    if not _is_loaded(str_ea):
        return None

    text = _read_cstr(str_ea)
    if not text or len(text) < min_strlen:
        return None
    if _printable_ratio(text) < 0.85:
        return None

    return {
        "entry_ea": ea,
        "ptr_field_ea": ptr_field_ea,
        "raw_ptr": raw_ptr,
        "str_ea": str_ea,
        "text": text,
        "layout": layout,
        "ptr_ea": ptr,
        "ptr_off": ptr_off,
        "str_off": str_off,
    }


def _entry_at(ea, min_strlen):
    best = None
    for ptr_off, str_off, layout in ENTRY_CANDIDATES:
        ent = _try_entry_candidate(ea, ptr_off, str_off, min_strlen, layout)
        if not ent:
            continue

        if best is None:
            best = ent
            continue

        # Prefer candidates with less pointer adjustment and longer text.
        cur_score = (len(best["text"]), -abs(best["str_ea"] - best["ptr_ea"]))
        new_score = (len(ent["text"]), -abs(ent["str_ea"] - ent["ptr_ea"]))
        if new_score > cur_score:
            best = ent

    return best


def _normalize_base(addr, stride, min_strlen, max_back=0):
    base = addr
    for _ in range(max_back):
        prev = base - stride
        if _entry_at(prev, min_strlen):
            base = prev
        else:
            break
    return base


def _parse_table(base, stride, max_entries, min_entries, min_strlen):
    out = []
    for i in range(max_entries):
        ea = base + i * stride
        ent = _entry_at(ea, min_strlen)
        if not ent:
            break
        out.append(ent)
    if len(out) < min_entries:
        return None
    return out


def _is_code_ea(ea):
    return idc.is_code(idc.get_full_flags(ea))


def _count_code_xrefs_to(dst):
    n = 0
    for x in idautils.XrefsTo(dst, ida_xref.XREF_ALL):
        if _is_code_ea(x.frm):
            n += 1
    return n


def _has_xref(src, dst):
    for x in idautils.XrefsFrom(src, ida_xref.XREF_ALL):
        if x.to == dst:
            return True
    return False


def _add_user_dref(src, dst):
    base_flags = ida_xref.XREF_USER if hasattr(ida_xref, "XREF_USER") else 0
    for dr_kind in (ida_xref.dr_O, ida_xref.dr_R):
        if ida_xref.add_dref(src, dst, dr_kind | base_flags):
            return True
    return False


def _item_head(ea):
    try:
        h = idc.get_item_head(ea)
        if h != BAD:
            return h
    except Exception:
        pass
    return ea


def _is_defined_item_head(ea):
    if ea in (None, BAD):
        return False
    if not _is_loaded(ea):
        return False
    if _item_head(ea) != ea:
        return False
    try:
        flags = idc.get_full_flags(ea)
    except Exception:
        return False
    return not ida_bytes.is_unknown(flags)


def _normalize_link_sources(cands):
    out = []
    seen = set()
    for ea in cands:
        if ea in (None, BAD):
            continue
        head = _item_head(ea)
        # Avoid add_dref "no defined item at from": keep only defined item heads.
        src_order = [ea] if ea == head else []
        src_order.append(head)
        for src in src_order:
            if src in (None, BAD) or src in seen:
                continue
            if not _is_defined_item_head(src):
                continue
            seen.add(src)
            out.append(src)
    return out


def _existing_xref_source(srcs, dst):
    for src in srcs:
        if _has_xref(src, dst):
            return src
    return BAD


def _add_user_dref_from_any(srcs, dst):
    for src in srcs:
        if _add_user_dref(src, dst):
            return src
    return BAD


def _set_comment(ea, text):
    ok = False
    for repeatable in (0, 1):
        try:
            ok = bool(idc.set_cmt(ea, text, repeatable)) or ok
        except Exception:
            pass
        try:
            ok = bool(ida_bytes.set_cmt(ea, text, repeatable)) or ok
        except Exception:
            pass
    return ok


def _clear_comment(ea):
    ok = False
    for repeatable in (0, 1):
        try:
            ok = bool(idc.set_cmt(ea, "", repeatable)) or ok
        except Exception:
            pass
        try:
            ok = bool(ida_bytes.set_cmt(ea, "", repeatable)) or ok
        except Exception:
            pass
    return ok


def _split_comment_lines(text, width=110):
    out = []
    for raw in str(text).splitlines():
        line = raw.strip()
        if not line:
            out.append("")
            continue
        out.extend(
            textwrap.wrap(
                line,
                width=width,
                break_long_words=False,
                break_on_hyphens=False,
            )
            or [""]
        )
    return out


def _set_extra_comment_lines(ea, lines, where=idc.E_PREV, clear_tail=True, max_tail=24):
    ok = False
    safe_lines = list(lines or [])
    for i, line in enumerate(safe_lines):
        try:
            ok = bool(idc.update_extra_cmt(ea, where + i, line)) or ok
        except Exception:
            pass
    if clear_tail:
        for i in range(len(safe_lines), len(safe_lines) + max_tail):
            try:
                cur = idc.get_extra_cmt(ea, where + i)
            except Exception:
                break
            if cur is None:
                break
            try:
                ok = bool(idc.del_extra_cmt(ea, where + i)) or ok
            except Exception:
                # Fallback for environments where delete may fail.
                try:
                    ok = bool(idc.update_extra_cmt(ea, where + i, "")) or ok
                except Exception:
                    pass
    return ok


def _set_entry_comment(ea, text):
    """Place string annotations above the exact __data member line."""
    ok = _clear_comment(ea)
    lines = _split_comment_lines(text, width=120)
    ok = _set_extra_comment_lines(ea, lines, where=idc.E_PREV, clear_tail=True) or ok
    return ok


def _set_code_ref_comment(ea, lines):
    """Place code-site summary above instruction line to avoid long inline comments."""
    ok = _clear_comment(ea)
    wrapped = []
    for line in lines:
        wrapped.extend(_split_comment_lines(line, width=120))
    ok = _set_extra_comment_lines(ea, wrapped, where=idc.E_PREV, clear_tail=True) or ok
    return ok


def _entry_comment_targets(ent, table_comment_ea):
    """Prefer direct member addresses so __data member lines get comments."""
    out = []
    for ea in (ent.get("entry_ea"), ent.get("ptr_field_ea")):
        if ea in (None, BAD, table_comment_ea):
            continue
        if not _is_loaded(ea):
            continue
        if ea in out:
            continue
        out.append(ea)
    return out


def _short_text(s, max_len=80):
    if s is None:
        return ""
    out = s.replace("\r", "\\r").replace("\n", "\\n")
    if len(out) <= max_len:
        return out
    return out[: max_len - 3] + "..."


def _resolve_function(function_hint):
    if function_hint is None:
        ea = ida_kernwin.get_screen_ea()
    else:
        ea = _ea(function_hint)
    fn = ida_funcs.get_func(ea)
    if not fn:
        raise RuntimeError(f"no function at: {hex(ea)}")
    return fn


def _merge_table(tables, base, stride, entries, src):
    cur = tables.get(base)
    if cur is None:
        tables[base] = {
            "base": base,
            "stride": stride,
            "entries": entries,
            "srcs": set([src]) if src else set(),
        }
        return
    if len(entries) > len(cur["entries"]):
        cur["entries"] = entries
        cur["stride"] = stride
    if src:
        cur["srcs"].add(src)


def _collect_code_xrefs(addr):
    out = set()
    for x in idautils.XrefsTo(addr, ida_xref.XREF_ALL):
        if _is_code_ea(x.frm):
            out.add(x.frm)
    return out


def _table_link_sources(mode, ent, base, header_ea, code_srcs):
    anchor = header_ea if header_ea not in (None, BAD) else base
    if mode == "ptr_field":
        return _normalize_link_sources([ent["ptr_field_ea"]])
    if mode == "entry":
        return _normalize_link_sources([ent["entry_ea"]])
    if mode == "table_header":
        return _normalize_link_sources([anchor])
    if mode == "table_base":
        return _normalize_link_sources([base])
    if mode == "table_code_src":
        return _normalize_link_sources(code_srcs)
    # auto: prefer template-side sources to preserve template->string relationship.
    return _normalize_link_sources([ent["ptr_field_ea"], ent["entry_ea"], anchor, base])


def _best_table_from_anchor(
    anchor, strides, min_entries, max_entries, min_strlen, header_scan_steps, max_back_steps
):
    best_entries = None
    best_base = None
    best_stride = None

    for stride in strides:
        for step in range(max(0, int(header_scan_steps)) + 1):
            probe = anchor + step * stride
            base = _normalize_base(probe, stride, min_strlen, max_back=max_back_steps)
            entries = _parse_table(base, stride, max_entries, min_entries, min_strlen)
            if entries and (best_entries is None or len(entries) > len(best_entries)):
                best_entries = entries
                best_base = base
                best_stride = stride

    return best_base, best_stride, best_entries


def _discover_from_function(
    fn, strides, min_entries, max_entries, min_strlen, header_scan_steps, max_back_steps
):
    tables = {}
    for src in idautils.FuncItems(fn.start_ea):
        for dref in idautils.DataRefsFrom(src):
            best_base, best_stride, best_entries = _best_table_from_anchor(
                dref,
                strides,
                min_entries,
                max_entries,
                min_strlen,
                header_scan_steps,
                max_back_steps,
            )
            if best_entries is not None:
                _merge_table(tables, best_base, best_stride, best_entries, src)
    return tables


def _discover_from_table_addrs(
    table_addrs,
    strides,
    min_entries,
    max_entries,
    min_strlen,
    header_scan_steps,
    max_back_steps,
):
    tables = {}
    for raw in table_addrs:
        addr = _ea(raw)
        best_base, best_stride, best_entries = _best_table_from_anchor(
            addr,
            strides,
            min_entries,
            max_entries,
            min_strlen,
            header_scan_steps,
            max_back_steps,
        )
        if best_entries is None:
            continue

        _merge_table(tables, best_base, best_stride, best_entries, None)
        srcs = _collect_code_xrefs(addr)
        if best_base != addr:
            srcs.update(_collect_code_xrefs(best_base))
        tables[best_base]["srcs"].update(srcs)

    return tables


def _read_uword_raw(ea):
    if not _is_loaded(ea):
        return BAD
    return ida_bytes.get_qword(ea) if PTR_SZ == 8 else ida_bytes.get_dword(ea)


def _declare_template_types():
    decls = r"""
typedef struct {
    unsigned long long tagged_len;
    const char *base_ptr;
} SwiftStaticStringRefV2;

typedef struct {
    unsigned long long reserved0;
    unsigned long long reserved1;
    unsigned long long count;
    unsigned long long capacity;
} SwiftArrayStringTemplateHeader;

typedef struct {
    SwiftArrayStringTemplateHeader hdr;
    SwiftStaticStringRefV2 items[2];
} SwiftArrayStringTemplate2;

typedef struct {
    SwiftArrayStringTemplateHeader hdr;
    SwiftStaticStringRefV2 items[3];
} SwiftArrayStringTemplate3;

typedef struct {
    SwiftArrayStringTemplateHeader hdr;
    SwiftStaticStringRefV2 items[4];
} SwiftArrayStringTemplate4;
"""
    try:
        # 0 means no special flags; returns 0 on success.
        return idc.parse_decls(decls, 0) == 0
    except Exception:
        return False


def _guess_template_header_for_table(base, entry_count):
    if entry_count < 2:
        return None
    if PTR_SZ != 8:
        return None

    header_ea = base - 0x20
    if not _is_loaded(header_ea):
        return None

    reserved0 = _read_uword_raw(header_ea)
    reserved1 = _read_uword_raw(header_ea + 8)
    count = _read_uword_raw(header_ea + 0x10)
    capacity = _read_uword_raw(header_ea + 0x18)
    if BAD in (reserved0, reserved1, count, capacity):
        return None

    # Typical static template header pattern for this table family.
    if count != entry_count:
        return None
    if capacity < entry_count or capacity > 0x1000:
        return None

    type_name = f"SwiftArrayStringTemplate{entry_count}"
    if entry_count not in (2, 3, 4):
        type_name = None

    return {
        "header_ea": header_ea,
        "entry_count": entry_count,
        "capacity": capacity,
        "reserved0": reserved0,
        "reserved1": reserved1,
        "type_name": type_name,
    }


def _apply_type(ea, ty):
    try:
        return bool(idc.SetType(ea, ty))
    except Exception:
        return False


def run(config=None):
    cfg = {
        "function": None,
        "table_addrs": [],
        "strides": [16, 24],
        "header_scan_steps": 4,
        "max_back_steps": 0,
        "min_entries": 2,
        "max_entries": 128,
        "min_strlen": 3,
        "one_source_per_table": True,
        "missing_only": True,
        "annotate_templates": False,
        "annotate_table_links": False,
        # auto, ptr_field, entry, table_header, table_base, table_code_src
        "table_link_source": "auto",
        "annotate_table_comments": False,
        "annotate_string_comments": False,
        "annotate_code_ref_comments": False,
        "dry_run": False,
    }
    if config:
        cfg.update(config)

    tables = {}

    if cfg["function"] is not False:
        fn = _resolve_function(cfg["function"])
        tables.update(
            _discover_from_function(
                fn,
                cfg["strides"],
                int(cfg["min_entries"]),
                int(cfg["max_entries"]),
                int(cfg["min_strlen"]),
                int(cfg["header_scan_steps"]),
                int(cfg["max_back_steps"]),
            )
        )

    if cfg["table_addrs"]:
        manual_tables = _discover_from_table_addrs(
            cfg["table_addrs"],
            cfg["strides"],
            int(cfg["min_entries"]),
            int(cfg["max_entries"]),
            int(cfg["min_strlen"]),
            int(cfg["header_scan_steps"]),
            int(cfg["max_back_steps"]),
        )
        for base, table in manual_tables.items():
            if base not in tables:
                tables[base] = table
                continue
            tables[base]["srcs"].update(table["srcs"])
            if len(table["entries"]) > len(tables[base]["entries"]):
                tables[base]["entries"] = table["entries"]
                tables[base]["stride"] = table["stride"]

    template_candidates = []
    table_header_by_base = {}
    template_applied = 0
    template_failed = []
    template_declared = None

    if cfg.get("annotate_templates"):
        if cfg["dry_run"]:
            template_declared = True
        else:
            template_declared = _declare_template_types()

        for base in sorted(tables):
            table = tables[base]
            info = _guess_template_header_for_table(base, len(table["entries"]))
            if info is None:
                continue

            out = {
                "base": hex(base),
                "header": hex(info["header_ea"]),
                "entry_count": info["entry_count"],
                "capacity": info["capacity"],
                "type_name": info["type_name"],
            }
            template_candidates.append(out)
            table_header_by_base[base] = info["header_ea"]

            if cfg["dry_run"]:
                continue
            if not template_declared:
                template_failed.append({**out, "error": "type declarations unavailable"})
                continue
            if not info["type_name"]:
                template_failed.append({**out, "error": "unsupported template arity"})
                continue
            if _apply_type(info["header_ea"], info["type_name"]):
                template_applied += 1
            else:
                template_failed.append({**out, "error": "SetType failed"})

    table_link_added_or_would_add = 0
    table_link_existing = 0
    table_link_failed = []
    table_comments_set_or_would_set = 0
    table_comments_failed = []
    entry_comments_set_or_would_set = 0
    entry_comments_failed = []
    string_comments_set_or_would_set = 0
    string_comments_failed = []
    code_ref_comments_set_or_would_set = 0
    code_ref_comments_failed = []

    link_src_mode = str(cfg.get("table_link_source", "auto")).strip().lower()
    if link_src_mode not in (
        "auto",
        "ptr_field",
        "entry",
        "table_header",
        "table_base",
        "table_code_src",
    ):
        link_src_mode = "auto"

    if (
        cfg.get("annotate_table_links")
        or cfg.get("annotate_table_comments")
        or cfg.get("annotate_string_comments")
        or cfg.get("annotate_code_ref_comments")
    ):
        for base in sorted(tables):
            table = tables[base]
            entries = table["entries"]
            header_ea = table_header_by_base.get(base, BAD)
            table_code_srcs = sorted(table["srcs"])
            comment_ea = header_ea if header_ea != BAD else base

            if cfg.get("annotate_table_comments"):
                table_comment_lines = [
                    (
                        f"Swift static string table: base={hex(base)} header={hex(comment_ea)} "
                        f"entries={len(entries)} stride={table['stride']} link_source={link_src_mode}"
                    ),
                ]
                for i, ent in enumerate(entries[:6]):
                    table_comment_lines.extend(
                        _split_comment_lines(
                            f"[{i}] {ent['layout']} str={hex(ent['str_ea'])} \"{_short_text(ent['text'], 140)}\"",
                            width=120,
                        )
                    )
                if cfg["dry_run"]:
                    table_comments_set_or_would_set += 1
                else:
                    ok = _clear_comment(comment_ea)
                    ok = _set_extra_comment_lines(
                        comment_ea, table_comment_lines, where=idc.E_PREV, clear_tail=True
                    ) or ok
                    if comment_ea != base:
                        ok = _clear_comment(base) or ok
                    if ok:
                        table_comments_set_or_would_set += 1
                    else:
                        table_comments_failed.append(
                            {"addr": hex(comment_ea), "base": hex(base), "error": "set_cmt failed"}
                        )

            if cfg.get("annotate_code_ref_comments") and table_code_srcs:
                code_comment_lines = [
                    f"Uses Swift string table {hex(comment_ea)} ({len(entries)} entries)",
                ]
                for i, ent in enumerate(entries[:6]):
                    code_comment_lines.append(
                        f"[{i}] {ent['layout']} str={hex(ent['str_ea'])} \"{_short_text(ent['text'], 140)}\""
                    )
                if cfg["dry_run"]:
                    code_ref_comments_set_or_would_set += len(table_code_srcs)
                else:
                    for src in table_code_srcs:
                        if _set_code_ref_comment(src, code_comment_lines):
                            code_ref_comments_set_or_would_set += 1
                        else:
                            code_ref_comments_failed.append(
                                {"addr": hex(src), "base": hex(base), "error": "set_cmt failed"}
                            )

            for idx, ent in enumerate(entries):
                dst = ent["str_ea"]
                link_sources = _table_link_sources(
                    link_src_mode, ent, base, comment_ea, table_code_srcs
                )
                fallback_sources = []
                if link_src_mode == "auto" and not link_sources:
                    fallback_sources = _normalize_link_sources(table_code_srcs)
                used_src = BAD

                if cfg.get("annotate_table_links"):
                    used_src = _existing_xref_source(link_sources, dst)
                    if used_src != BAD:
                        table_link_existing += 1
                    elif cfg["dry_run"]:
                        table_link_added_or_would_add += 1
                    else:
                        used_src = _add_user_dref_from_any(link_sources, dst)
                        if used_src == BAD and fallback_sources:
                            used_src = _add_user_dref_from_any(fallback_sources, dst)
                        if used_src != BAD:
                            table_link_added_or_would_add += 1
                        else:
                            table_link_failed.append(
                                {
                                    "src_candidates": [hex(x) for x in (link_sources + fallback_sources)[:6]],
                                    "dst": hex(dst),
                                    "entry": hex(ent["entry_ea"]),
                                    "text": _short_text(ent["text"], 60),
                                }
                            )

                if cfg.get("annotate_table_comments"):
                    if used_src == BAD and link_sources:
                        used_src = link_sources[0]
                    entry_comment = (
                        f"[{idx}] {ent['layout']} src={hex(used_src)} ptr={hex(ent['ptr_ea'])} "
                        f"str={hex(dst)} \"{_short_text(ent['text'], 84)}\""
                    )
                    if cfg["dry_run"]:
                        entry_comments_set_or_would_set += 1
                    else:
                        entry_targets = _entry_comment_targets(ent, comment_ea)
                        if not entry_targets:
                            entry_comments_set_or_would_set += 1
                        else:
                            ok = False
                            for cmt_ea in entry_targets:
                                ok = _set_entry_comment(cmt_ea, entry_comment) or ok
                            if ok:
                                entry_comments_set_or_would_set += 1
                            else:
                                entry_comments_failed.append(
                                    {"addr": hex(ent["entry_ea"]), "error": "set_cmt failed"}
                                )

                if cfg.get("annotate_string_comments"):
                    str_comment = (
                        f"Swift table {hex(comment_ea)}[{idx}] <- {hex(ent['entry_ea'])} "
                        f"layout={ent['layout']} len={len(ent['text'])}"
                    )
                    if cfg["dry_run"]:
                        string_comments_set_or_would_set += 1
                    else:
                        if _set_comment(dst, str_comment):
                            string_comments_set_or_would_set += 1
                        else:
                            string_comments_failed.append({"addr": hex(dst), "error": "set_cmt failed"})

    added_or_would_add = 0
    skipped_existing = 0
    skipped_has_code_xref = 0
    failed = []

    for base in sorted(tables):
        table = tables[base]
        srcs = sorted(table["srcs"])
        if not srcs:
            continue
        if cfg["one_source_per_table"]:
            srcs = srcs[:1]

        for ent in table["entries"]:
            dst = ent["str_ea"]
            if cfg["missing_only"] and _count_code_xrefs_to(dst) > 0:
                skipped_has_code_xref += 1
                continue

            for src in srcs:
                if _has_xref(src, dst):
                    skipped_existing += 1
                    continue

                if cfg["dry_run"]:
                    added_or_would_add += 1
                    continue

                if _add_user_dref(src, dst):
                    added_or_would_add += 1
                else:
                    failed.append(
                        {
                            "src": hex(src),
                            "dst": hex(dst),
                            "text": ent["text"][:80],
                        }
                    )

    return {
        "tables_found": len(tables),
        "template_declared": template_declared,
        "template_candidates": template_candidates,
        "template_applied": template_applied,
        "template_failed": template_failed[:50],
        "table_link_added_or_would_add": table_link_added_or_would_add,
        "table_link_existing": table_link_existing,
        "table_link_failed": table_link_failed[:50],
        "table_comments_set_or_would_set": table_comments_set_or_would_set,
        "table_comments_failed": table_comments_failed[:50],
        "entry_comments_set_or_would_set": entry_comments_set_or_would_set,
        "entry_comments_failed": entry_comments_failed[:50],
        "string_comments_set_or_would_set": string_comments_set_or_would_set,
        "string_comments_failed": string_comments_failed[:50],
        "code_ref_comments_set_or_would_set": code_ref_comments_set_or_would_set,
        "code_ref_comments_failed": code_ref_comments_failed[:50],
        "added_or_would_add": added_or_would_add,
        "skipped_existing": skipped_existing,
        "skipped_has_code_xref": skipped_has_code_xref,
        "failed": len(failed),
        "failed_items": failed[:50],
        "table_summary": [
            {
                "base": hex(t["base"]),
                "stride": t["stride"],
                "entries": len(t["entries"]),
                "layouts": sorted(set(e["layout"] for e in t["entries"])),
                "srcs": [hex(x) for x in sorted(t["srcs"])[:5]],
            }
            for t in sorted(tables.values(), key=lambda item: item["base"])
        ],
    }


# py_eval entrypoint
# Example overrides:
# config = {"function": None, "dry_run": True, "annotate_templates": True, "annotate_table_links": True, "table_link_source": "auto", "annotate_table_comments": True, "annotate_string_comments": True, "annotate_code_ref_comments": True, "table_addrs": ["0x<table_ea>"]}
config = {}
try:
    result = run(config)
except RuntimeError as e:
    # Keep run_path/exec robust when cursor is on data, not in a function.
    if config.get("function", None) is None and "no function at" in str(e):
        result = run({"function": False, **config})
        result["note"] = "cursor is not in a function; set function or move cursor"
    else:
        raise
