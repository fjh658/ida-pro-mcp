"""Tool definition parser.

Parse tool/resource definitions from ida_mcp/api_*.py files and generate
MCP tool schemas for registration in server.py.

This parser does not import IDA modules; it only parses source code.
"""

import ast
import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ToolParam:
    """Tool parameter definition."""

    name: str
    type_str: str  # Raw type string
    description: str
    required: bool = True
    default: Any = None


@dataclass
class ToolDef:
    """Tool definition."""

    name: str
    description: str
    params: list[ToolParam] = field(default_factory=list)
    return_type: str = "Any"
    is_unsafe: bool = False
    source_file: str = ""


@dataclass
class ResourceDef:
    """Resource definition."""

    uri: str
    name: str
    description: str
    return_type: str = "Any"
    source_file: str = ""


@dataclass
class TypedDictFieldDef:
    """TypedDict field definition."""

    type_str: str
    description: str = ""
    required: bool = True


@dataclass
class TypedDictDef:
    """TypedDict definition."""

    name: str
    fields: dict[str, TypedDictFieldDef] = field(default_factory=dict)


# Lazy cache to avoid re-parsing source files repeatedly.
_TYPED_DICT_CACHE: Optional[dict[str, TypedDictDef]] = None


def _base_name(name: str) -> str:
    """Return the unqualified type name."""
    return name.strip().split(".")[-1]


def _split_generic(type_str: str) -> tuple[str, Optional[str]]:
    """Split `Type[Inner]` into (Type, Inner), preserving nested brackets."""
    s = type_str.strip()
    if not s.endswith("]"):
        return s, None

    depth = 0
    bracket_pos = -1
    for i, ch in enumerate(s):
        if ch == "[":
            if depth == 0:
                bracket_pos = i
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth < 0:
                return s, None

    if depth != 0 or bracket_pos <= 0:
        return s, None

    return s[:bracket_pos].strip(), s[bracket_pos + 1 : -1].strip()


def _split_top_level(expr: str, sep: str) -> list[str]:
    """Split by separator while respecting [] nesting."""
    parts: list[str] = []
    depth = 0
    start = 0

    for i, ch in enumerate(expr):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            part = expr[start:i].strip()
            if part:
                parts.append(part)
            start = i + 1

    tail = expr[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _dedupe_schemas(schemas: list[dict]) -> list[dict]:
    """Deduplicate schema objects while preserving order."""
    result: list[dict] = []
    seen: set[str] = set()

    for schema in schemas:
        key = json.dumps(schema, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        result.append(schema)

    return result


def _parse_literal_token(token: str) -> Any:
    """Parse a Literal token into Python scalar value if possible."""
    t = token.strip()
    if not t:
        raise ValueError("empty")

    if (t.startswith("'") and t.endswith("'")) or (t.startswith('"') and t.endswith('"')):
        return t[1:-1]

    if t == "True":
        return True
    if t == "False":
        return False
    if t in ("None", "NoneType"):
        return None

    try:
        return int(t, 0)
    except ValueError:
        pass

    try:
        return float(t)
    except ValueError as e:
        raise ValueError("unsupported literal token") from e


def _node_to_type_str(node: ast.expr) -> str:
    """Convert an AST node to a type string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.Subscript):
        base = _node_to_type_str(node.value)
        if isinstance(node.slice, ast.Tuple):
            args = ", ".join(_node_to_type_str(e) for e in node.slice.elts)
        else:
            args = _node_to_type_str(node.slice)
        return f"{base}[{args}]"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        # Union type: int | str
        left = _node_to_type_str(node.left)
        right = _node_to_type_str(node.right)
        return f"{left} | {right}"
    if isinstance(node, ast.Attribute):
        return f"{_node_to_type_str(node.value)}.{node.attr}"
    return "Any"


def _parse_annotation_node(node: ast.expr) -> tuple[str, str]:
    """Parse annotation and return (type_str, description)."""
    # Annotated[type, "description"]
    if isinstance(node, ast.Subscript):
        base = _node_to_type_str(node.value)
        if _base_name(base) == "Annotated":
            if isinstance(node.slice, ast.Tuple) and len(node.slice.elts) >= 2:
                type_node = node.slice.elts[0]
                desc_node = node.slice.elts[1]
                type_str = _node_to_type_str(type_node)
                description = ""
                if isinstance(desc_node, ast.Constant):
                    description = str(desc_node.value)
                return type_str, description
        return _node_to_type_str(node), ""

    return _node_to_type_str(node), ""


def _unwrap_required_wrapper(type_str: str, default_required: bool) -> tuple[str, bool]:
    """Unwrap Required[T] / NotRequired[T] wrappers if present."""
    base, inner = _split_generic(type_str)
    bname = _base_name(base)
    if inner is None:
        return type_str, default_required
    if bname == "NotRequired":
        return inner, False
    if bname == "Required":
        return inner, True
    return type_str, default_required


def _is_typeddict_class(node: ast.ClassDef) -> bool:
    for base in node.bases:
        if _base_name(_node_to_type_str(base)) == "TypedDict":
            return True
    return False


def _parse_typed_dicts_from_file(filepath: str) -> dict[str, TypedDictDef]:
    """Parse TypedDict class definitions from a source file."""
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    result: dict[str, TypedDictDef] = {}

    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        if not _is_typeddict_class(node):
            continue

        total = True
        for kw in node.keywords:
            if kw.arg == "total" and isinstance(kw.value, ast.Constant):
                total = bool(kw.value.value)

        td = TypedDictDef(name=node.name)

        for stmt in node.body:
            if not isinstance(stmt, ast.AnnAssign):
                continue
            if not isinstance(stmt.target, ast.Name):
                continue

            field_name = stmt.target.id
            type_str, description = _parse_annotation_node(stmt.annotation)
            type_str, required = _unwrap_required_wrapper(type_str, total)
            td.fields[field_name] = TypedDictFieldDef(
                type_str=type_str,
                description=description,
                required=required,
            )

        result[td.name] = td

    return result


def _load_typed_dict_defs() -> dict[str, TypedDictDef]:
    """Load TypedDict definitions from ida_mcp sources (AST-only).

    We intentionally parse source files instead of importing ida_mcp modules:
    importing those modules outside IDA can fail (idaapi dependency) and would
    also execute module-level side effects. The AST path keeps schema generation
    deterministic and usable in non-IDA environments (tests, CI, MCP startup).
    """
    global _TYPED_DICT_CACHE
    if _TYPED_DICT_CACHE is not None:
        return _TYPED_DICT_CACHE

    defs: dict[str, TypedDictDef] = {}
    api_dir = os.path.join(os.path.dirname(__file__), "ida_mcp")

    if os.path.isdir(api_dir):
        for filename in sorted(os.listdir(api_dir)):
            if not filename.endswith(".py"):
                continue
            filepath = os.path.join(api_dir, filename)
            defs.update(_parse_typed_dicts_from_file(filepath))

    _TYPED_DICT_CACHE = defs
    return defs


class ToolParser(ast.NodeVisitor):
    """AST parser that extracts functions decorated with @tool and @resource."""

    def __init__(self, source_file: str = ""):
        self.tools: list[ToolDef] = []
        self.resources: list[ResourceDef] = []
        self.source_file = source_file
        self._unsafe_funcs: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definitions."""
        decorators = self._get_decorators(node)

        # Check whether @unsafe decorator exists
        is_unsafe = "unsafe" in decorators

        # Check @tool decorator
        if "tool" in decorators:
            tool_def = self._parse_tool(node, is_unsafe)
            if tool_def:
                self.tools.append(tool_def)

        # Check @resource decorator
        resource_uri = decorators.get("resource")
        if resource_uri:
            resource_def = self._parse_resource(node, resource_uri)
            if resource_def:
                self.resources.append(resource_def)

        self.generic_visit(node)

    def _get_decorators(self, node: ast.FunctionDef) -> dict[str, Any]:
        """Get decorators attached to a function."""
        decorators = {}
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                # @tool, @unsafe, @idasync
                decorators[dec.id] = True
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    # @resource("uri"), @ext("group")
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        decorators[dec.func.id] = dec.args[0].value
                    else:
                        decorators[dec.func.id] = True
        return decorators

    def _parse_tool(self, node: ast.FunctionDef, is_unsafe: bool) -> Optional[ToolDef]:
        """Parse a tool function."""
        name = node.name
        description = ast.get_docstring(node) or f"Call {name}"
        params = self._parse_params(node)
        return_type = self._get_return_type(node)

        return ToolDef(
            name=name,
            description=description.strip(),
            params=params,
            return_type=return_type,
            is_unsafe=is_unsafe,
            source_file=self.source_file,
        )

    def _parse_resource(self, node: ast.FunctionDef, uri: str) -> Optional[ResourceDef]:
        """Parse a resource function."""
        name = node.name
        description = ast.get_docstring(node) or f"Resource {uri}"
        return_type = self._get_return_type(node)

        return ResourceDef(
            uri=uri,
            name=name,
            description=description.strip(),
            return_type=return_type,
            source_file=self.source_file,
        )

    def _parse_params(self, node: ast.FunctionDef) -> list[ToolParam]:
        """Parse function parameters."""
        params = []
        defaults_offset = len(node.args.args) - len(node.args.defaults)

        for i, arg in enumerate(node.args.args):
            # Skip self parameter
            if arg.arg == "self":
                continue

            param_name = arg.arg
            type_str = "Any"
            description = ""

            # Parse type annotation
            if arg.annotation:
                type_str, description = self._parse_annotation(arg.annotation)

            # Check for default value
            default_idx = i - defaults_offset
            has_default = default_idx >= 0 and default_idx < len(node.args.defaults)
            default_value = None
            if has_default:
                default_node = node.args.defaults[default_idx]
                default_value = self._get_constant_value(default_node)

            params.append(
                ToolParam(
                    name=param_name,
                    type_str=type_str,
                    description=description,
                    required=not has_default,
                    default=default_value,
                )
            )

        return params

    def _parse_annotation(self, node: ast.expr) -> tuple[str, str]:
        """Parse type annotation and return (type_str, description)."""
        return _parse_annotation_node(node)

    def _node_to_type_str(self, node: ast.expr) -> str:
        """Convert an AST node to a type string."""
        return _node_to_type_str(node)

    def _get_return_type(self, node: ast.FunctionDef) -> str:
        """Get return type."""
        if node.returns:
            return self._node_to_type_str(node.returns)
        return "Any"

    def _get_constant_value(self, node: ast.expr) -> Any:
        """Get constant value."""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.List):
            return [self._get_constant_value(e) for e in node.elts]
        if isinstance(node, ast.Dict):
            return {
                self._get_constant_value(k): self._get_constant_value(v)
                for k, v in zip(node.keys, node.values)
                if k is not None
            }
        if isinstance(node, ast.Name) and node.id == "None":
            return None
        return None


def parse_api_file(filepath: str) -> tuple[list[ToolDef], list[ResourceDef]]:
    """Parse one API file."""
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"[tool_registry] Parse error {filepath}: {e}")
        return [], []

    parser = ToolParser(source_file=os.path.basename(filepath))
    parser.visit(tree)

    return parser.tools, parser.resources


def parse_all_api_files(api_dir: str) -> tuple[list[ToolDef], list[ResourceDef]]:
    """Parse all api_*.py files in a directory."""
    all_tools: list[ToolDef] = []
    all_resources: list[ResourceDef] = []

    if not os.path.isdir(api_dir):
        print(f"[tool_registry] Directory does not exist: {api_dir}")
        return all_tools, all_resources

    for filename in sorted(os.listdir(api_dir)):
        if filename.startswith("api_") and filename.endswith(".py"):
            # Skip api_instances.py (connection management, not an IDA tool module)
            if filename == "api_instances.py":
                continue

            filepath = os.path.join(api_dir, filename)
            tools, resources = parse_api_file(filepath)
            all_tools.extend(tools)
            all_resources.extend(resources)

    return all_tools, all_resources


def type_str_to_json_schema(
    type_str: str,
    typed_dict_defs: Optional[dict[str, TypedDictDef]] = None,
    stack: Optional[set[str]] = None,
) -> dict:
    """Convert a parsed Python type string into JSON Schema.

    Input examples:
      - "int"
      - "list[MemoryRead] | MemoryRead"
      - "Optional[list[str]]"
      - "Dict[str, ListQuery]"

    Design notes:
      - Keep unions explicit via ``anyOf`` so MCP clients can choose valid
        structured argument forms instead of collapsing to a single "object".
      - Expand known TypedDict names into full object schemas with field-level
        required information, descriptions, and ``additionalProperties: false``.
      - Use a conservative fallback ``{"type": "object"}`` for unknown complex
        symbols so callers still get a valid schema object.
    """
    t = type_str.strip()
    if not t:
        return {}

    if typed_dict_defs is None:
        typed_dict_defs = _load_typed_dict_defs()
    if stack is None:
        stack = set()

    # Handle top-level unions first (A | B | C) so nested branches are resolved
    # independently and then merged into a single ``anyOf``.
    union_parts = _split_top_level(t, "|")
    if len(union_parts) > 1:
        schemas = [
            type_str_to_json_schema(part, typed_dict_defs=typed_dict_defs, stack=stack)
            for part in union_parts
        ]
        schemas = _dedupe_schemas(schemas)
        if len(schemas) == 1:
            return schemas[0]
        return {"anyOf": schemas}

    base, inner = _split_generic(t)
    bname = _base_name(base)

    # Optional[T] is encoded as ``T | null`` to preserve nullability in schema.
    if bname == "Optional" and inner is not None:
        schemas = _dedupe_schemas(
            [
                type_str_to_json_schema(inner, typed_dict_defs=typed_dict_defs, stack=stack),
                {"type": "null"},
            ]
        )
        if len(schemas) == 1:
            return schemas[0]
        return {"anyOf": schemas}

    # Required[T] / NotRequired[T] are field-level metadata wrappers used in
    # TypedDict definitions. For schema shape we unwrap and recurse into T.
    if bname in {"Required", "NotRequired"} and inner is not None:
        return type_str_to_json_schema(inner, typed_dict_defs=typed_dict_defs, stack=stack)

    # list[T] -> JSON array with recursively resolved item schema.
    if bname in {"list", "List"} and inner is not None:
        return {
            "type": "array",
            "items": type_str_to_json_schema(
                inner,
                typed_dict_defs=typed_dict_defs,
                stack=stack,
            ),
        }

    # dict[K, V] -> JSON object. JSON Schema cannot express arbitrary key types
    # from Python dict generics, so we preserve the value schema via
    # ``additionalProperties`` and ignore K.
    if bname in {"dict", "Dict"} and inner is not None:
        generic_args = _split_top_level(inner, ",")
        value_type = generic_args[1] if len(generic_args) >= 2 else "Any"
        return {
            "type": "object",
            "additionalProperties": type_str_to_json_schema(
                value_type,
                typed_dict_defs=typed_dict_defs,
                stack=stack,
            ),
        }

    # Literal[a, b, c] -> enum when all literal tokens can be parsed safely.
    if bname == "Literal" and inner is not None:
        values: list[Any] = []
        for token in _split_top_level(inner, ","):
            try:
                values.append(_parse_literal_token(token))
            except ValueError:
                values = []
                break
        if values:
            return {"enum": values}

    primitive_map = {
        "str": {"type": "string"},
        "int": {"type": "integer"},
        "float": {"type": "number"},
        "bool": {"type": "boolean"},
        "None": {"type": "null"},
        "NoneType": {"type": "null"},
        "Any": {},
    }
    if t in primitive_map:
        return primitive_map[t]

    # Resolve TypedDict names by unqualified class name. ``stack`` prevents
    # infinite recursion for self-referential or cyclic type aliases.
    td_name = _base_name(base)
    td_def = typed_dict_defs.get(td_name)
    if td_def and td_name not in stack:
        next_stack = set(stack)
        next_stack.add(td_name)

        properties: dict[str, dict] = {}
        required: list[str] = []
        for field_name, field_def in td_def.fields.items():
            field_schema = type_str_to_json_schema(
                field_def.type_str,
                typed_dict_defs=typed_dict_defs,
                stack=next_stack,
            )
            if field_def.description:
                field_schema = dict(field_schema)
                field_schema["description"] = field_def.description
            properties[field_name] = field_schema
            if field_def.required:
                required.append(field_name)

        result = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            result["required"] = required
        return result

    # Unknown complex type fallback. We keep this permissive to avoid producing
    # invalid schemas when encountering symbols we cannot resolve statically.
    return {"type": "object"}


def tool_to_mcp_schema(tool: ToolDef) -> dict:
    """Convert ToolDef into an MCP-compatible tool schema object.

    This function is intentionally parser-driven. It converts the static type
    strings extracted from source into JSON Schema *before* runtime wrappers are
    built. Downstream code can then reuse this schema to avoid Any-annotation
    type loss in dynamically generated call wrappers.
    """
    properties = {}
    required = []

    typed_dict_defs = _load_typed_dict_defs()

    for param in tool.params:
        prop = type_str_to_json_schema(param.type_str, typed_dict_defs=typed_dict_defs)
        if param.description:
            prop["description"] = param.description
        if param.default is not None:
            prop["default"] = param.default
        properties[param.name] = prop

        if param.required:
            required.append(param.name)

    schema = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
        },
    }

    if required:
        schema["inputSchema"]["required"] = required

    return schema


def resource_to_mcp_schema(resource: ResourceDef) -> dict:
    """Convert ResourceDef into MCP resource schema."""
    return {
        "uri": resource.uri,
        "name": resource.name,
        "description": resource.description,
    }


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    # Get API directory
    script_dir = os.path.dirname(os.path.realpath(__file__))
    api_dir = os.path.join(script_dir, "ida_mcp")

    print(f"Parsing directory: {api_dir}")
    tools, resources = parse_all_api_files(api_dir)

    print(f"\nFound {len(tools)} tools:")
    for t in tools:
        params_str = ", ".join(f"{p.name}: {p.type_str}" for p in t.params)
        print(f"  - {t.name}({params_str}) -> {t.return_type}")
        if t.is_unsafe:
            print("    [UNSAFE]")

    print(f"\nFound {len(resources)} resources:")
    for r in resources:
        print(f"  - {r.uri} -> {r.name}")
