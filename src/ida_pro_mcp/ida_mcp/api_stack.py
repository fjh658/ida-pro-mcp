"""Stack frame operations for IDA Pro MCP.

This module provides batch operations for managing stack frame variables,
including reading, creating, and deleting stack variables in functions.
"""

from typing import Annotated
import ida_frame
import idaapi

from .rpc import tool
from .sync import idasync
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    StackVarDecl,
    StackVarDelete,
    get_stack_frame_variables_internal,
    has_func_frame,
    get_frame_member_info,
    is_special_frame_member_compat,
    delete_frame_member_compat,
    define_stkvar_compat,
)


# ============================================================================
# Stack Frame Operations
# ============================================================================


@tool
@idasync
def stack_frame(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Get stack vars"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            vars = get_stack_frame_variables_internal(ea, True)
            results.append({"addr": addr, "vars": vars})
        except Exception as e:
            results.append({"addr": addr, "vars": None, "error": str(e)})

    return results


@tool
@idasync
def declare_stack(
    items: list[StackVarDecl] | StackVarDecl,
):
    """Create stack vars"""
    items = normalize_dict_list(items)
    results = []

    for item in items:
        fn_addr = item.get("addr", "")
        offset = item.get("offset", "")
        var_name = item.get("name", "")
        type_name = item.get("ty", "")

        try:
            func = idaapi.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            ea = parse_address(offset)
            if not has_func_frame(func):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            tif = get_type_by_name(type_name)
            if not define_stkvar_compat(func, var_name, ea, tif):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to define"}
                )
                continue

            results.append({"addr": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results


@tool
@idasync
def delete_stack(
    items: list[StackVarDelete] | StackVarDelete,
):
    """Delete stack vars"""

    items = normalize_dict_list(items)
    results = []

    for item in items:
        fn_addr = item.get("addr", "")
        var_name = item.get("name", "")

        try:
            func = idaapi.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            member_info = get_frame_member_info(func, var_name)
            if not member_info:
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} not found",
                    }
                )
                continue

            tid = int(member_info["tid"])
            if is_special_frame_member_compat(tid):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is special frame member",
                    }
                )
                continue

            offset = int(member_info["offset"])
            size = int(member_info["size"])
            if ida_frame.is_funcarg_off(func, offset):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is argument member",
                    }
                )
                continue

            if not delete_frame_member_compat(func, offset, size):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to delete"}
                )
                continue

            results.append({"addr": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results
