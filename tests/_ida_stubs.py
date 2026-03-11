"""Stub IDA modules so tests can import ida_mcp without IDA installed.

Instead of maintaining a hardcoded list of IDA module names (which varies
across IDA versions), we install an import hook that auto-creates stub
modules for any ``ida_*``, ``idaapi``, ``idc``, or ``idautils`` import.

The stub IDA version defaults to "9.0" but can be overridden via the
``IDA_STUB_VERSION`` environment variable or by calling ``install("8.3")``.
This controls which code paths compat.py takes:
  - "8.3": < 8.4 path (oldest supported)
  - "8.4": IDA_GE_84 path
  - "8.5": IDA_GE_85 path
  - "9.0"+: IDA_GE_90 path (default)
"""

import importlib.abc
import importlib.machinery
import os
import sys
import types

_PREFIXES = ("ida_", "idaapi", "idc", "idautils")

# Pre-defined stub attributes needed at module level by ida_mcp code
_CLASS_STUBS: dict[str, dict[str, type]] = {
    "ida_hexrays": {
        "user_lvar_modifier_t": type("user_lvar_modifier_t", (), {}),
        "vd_printer_t": type("vd_printer_t", (), {}),
    },
    "ida_dbg": {
        "DBG_Hooks": type(
            "DBG_Hooks", (), {"hook": lambda s: None, "unhook": lambda s: None}
        ),
    },
}

# Mutable — version set by install()
_FUNC_STUBS: dict[str, dict[str, object]] = {}


def _is_ida_module(fullname: str) -> bool:
    # Don't intercept our own package
    if fullname.startswith("ida_pro_mcp"):
        return False
    return any(fullname == p or fullname.startswith(p) for p in _PREFIXES)


class _IDAStubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        mod = types.ModuleType(spec.name)
        for attr, val in _CLASS_STUBS.get(spec.name, {}).items():
            setattr(mod, attr, val)
        for attr, val in _FUNC_STUBS.get(spec.name, {}).items():
            setattr(mod, attr, val)
        return mod

    def exec_module(self, module):
        pass


class _IDAStubFinder(importlib.abc.MetaPathFinder):
    """Meta path finder that creates empty stub modules for IDA imports."""

    def find_spec(self, fullname, path, target=None):
        if _is_ida_module(fullname):
            return importlib.machinery.ModuleSpec(
                fullname, _IDAStubLoader(), origin="ida_stubs"
            )
        return None


_installed = False


def install(version: str | None = None):
    """Install the IDA stub import hook.

    Args:
        version: IDA version string (e.g. "8.3", "8.5", "9.0").
                 Defaults to env var ``IDA_STUB_VERSION`` or "9.0".
                 Controls which compat.py code paths are exercised.

    Safe to call multiple times (only the first call takes effect,
    since compat.py reads the version at import time).
    """
    global _installed
    if _installed:
        return

    if version is None:
        version = os.environ.get("IDA_STUB_VERSION", "9.0")

    _FUNC_STUBS["idaapi"] = {
        "get_kernel_version": lambda v=version: v,
    }

    sys.meta_path.insert(0, _IDAStubFinder())
    _installed = True
