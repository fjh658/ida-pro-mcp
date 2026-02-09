"""IDA Pro MCP Server

Broker architecture:
  - Broker mode (--broker): Only starts HTTP, holds REGISTRY; both IDA and MCP clients connect to this process.
  - MCP mode (default): stdio only, no port binding; requests are forwarded to the Broker via the Broker client.

  Cursor --stdio--> server.py --HTTP--> Broker <--HTTP+SSE-- IDA Plugin
"""

import os
import sys
import json
import argparse
import inspect
import socket
import subprocess
import threading
import time
from typing import Optional, BinaryIO

# Handle both direct execution and package execution
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if __name__ == "__main__" or __package__ is None:
    sys.path.insert(0, os.path.dirname(SCRIPT_DIR))
    from ida_pro_mcp.http_server import IDAHttpServer, REGISTRY
    from ida_pro_mcp.tool_registry import parse_all_api_files, tool_to_mcp_schema, ToolDef
    from ida_pro_mcp.install import install_ida_plugin, install_mcp_servers, print_mcp_config
    from ida_pro_mcp.broker_client import BrokerClient
else:
    from .http_server import IDAHttpServer, REGISTRY
    from .tool_registry import parse_all_api_files, tool_to_mcp_schema, ToolDef
    from .install import install_ida_plugin, install_mcp_servers, print_mcp_config
    from .broker_client import BrokerClient

# Import MCP implementation
sys.path.insert(0, os.path.join(SCRIPT_DIR, "ida_mcp"))
from zeromcp import McpServer
from zeromcp.jsonrpc import JsonRpcResponse
sys.path.pop(0)


# ============================================================================
# stdio output (for sending notifications)
# ============================================================================

_stdio_stdout: Optional[BinaryIO] = None
_stdio_lock = threading.Lock()


def send_notification(method: str, params: dict = None):
    """Send MCP notification to client (stdio)"""
    if _stdio_stdout is None:
        return
    
    notification = {"jsonrpc": "2.0", "method": method}
    if params:
        notification["params"] = params
    
    try:
        with _stdio_lock:
            _stdio_stdout.write(json.dumps(notification).encode("utf-8") + b"\n")
            _stdio_stdout.flush()
    except Exception as e:
        print(f"[MCP] Failed to send notification: {e}", file=sys.stderr)


# ============================================================================
# MCP Server
# ============================================================================

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

# HTTP server instance (used only in Broker mode)
HTTP_SERVER: Optional[IDAHttpServer] = None

# Broker client (used in MCP mode, requests instance list and forwards IDA requests to Broker)
_broker_client: Optional[BrokerClient] = None


def _broker():
    """Get Broker client, always available in MCP mode"""
    global _broker_client
    if _broker_client is None:
        _broker_client = BrokerClient(
            os.environ.get("IDA_MCP_BROKER_URL", "http://127.0.0.1:13337"),
            10.0,
        )
    return _broker_client


# Register instance management tools (via Broker client, no local REGISTRY needed)
@mcp.tool
def instance_list() -> list[dict]:
    """List all connected IDA instances. Local tool, no IDA connection required."""
    return _broker().list_instances()


@mcp.tool
def instance_current() -> dict:
    """Get current active IDA instance info. Local tool, no IDA connection required."""
    out = _broker().get_current()
    if out is None:
        return {"error": "Broker unavailable. Please start it first: ida-pro-mcp --broker"}
    if out.get("error"):
        return {"error": out["error"]}
    return out


@mcp.tool
def instance_switch(instance_id: str) -> dict:
    """Switch to specified IDA instance. Local tool, no IDA connection required."""
    return _broker().set_current(instance_id)


@mcp.tool
def instance_info(instance_id: str) -> dict:
    """Get detailed info for specified IDA instance. Local tool, no IDA connection required."""
    instances = _broker().list_instances()
    current = _broker().get_current()
    current_id = (current or {}).get("instance_id")
    for inst in instances:
        if inst.get("instance_id") == instance_id:
            return {**inst, "is_current": inst.get("instance_id") == current_id}
    return {"error": f"Instance not found: {instance_id}"}


# ============================================================================
# Dynamically register IDA tools and resources
# ============================================================================

_IDA_API_DIR = os.path.join(SCRIPT_DIR, "ida_mcp")
_IDA_TOOLS, _IDA_RESOURCES = parse_all_api_files(_IDA_API_DIR)

UNSAFE_TOOLS = {t.name for t in _IDA_TOOLS if t.is_unsafe}
IDA_TOOLS: set[str] = set()
_UNSAFE_ENABLED = False


def _build_ida_tool_input_schema(tool_def: ToolDef) -> dict:
    """Build explicit input schema for IDA tool wrappers.

    This preserves parser-derived types (int/list/bool/...) instead of relying
    on runtime Any annotations, and injects broker-only `_instance` selector.
    """
    # Build the "real" schema from static parser output. This path keeps
    # declared API types (including nested unions/TypedDicts) intact.
    base_input_schema = tool_to_mcp_schema(tool_def)["inputSchema"]
    properties = dict(base_input_schema.get("properties", {}))

    # `_instance` is a broker-side routing control and must not be forwarded to
    # IDA tool handlers. We expose it in schema as optional string|null.
    properties["_instance"] = {
        "anyOf": [{"type": "string"}, {"type": "null"}],
        "description": "Target IDA instance ID (e.g. 'ida-86893'). If omitted, uses the current active instance.",
    }

    # Ensure `_instance` is never marked as required, even if upstream schema
    # were to include it accidentally.
    required = [
        key
        for key in base_input_schema.get("required", [])
        if key != "_instance"
    ]

    # Return a defensive copy because McpServer schema generation mutates/copies
    # sub-structures and we do not want shared references.
    input_schema = dict(base_input_schema)
    input_schema["type"] = "object"
    input_schema["properties"] = properties
    input_schema["required"] = required
    return input_schema


def _json_schema_to_runtime_annotation(schema: dict):
    """Best-effort JSON Schema -> runtime annotation mapping.

    Some MCP hosts incorrectly derive parameter types from Python annotations
    instead of `tools/list` inputSchema. We keep parser-driven schema as source
    of truth, but expose close-enough runtime hints for compatibility.
    """
    from typing import Any as AnyType

    if not isinstance(schema, dict):
        return AnyType

    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and any_of:
        union_type = None
        for branch in any_of:
            branch_type = _json_schema_to_runtime_annotation(branch)
            if union_type is None:
                union_type = branch_type
            else:
                try:
                    union_type = union_type | branch_type
                except TypeError:
                    return AnyType
        return union_type if union_type is not None else AnyType

    schema_type = schema.get("type")
    if schema_type == "integer":
        return int
    if schema_type == "number":
        return float
    if schema_type == "string":
        return str
    if schema_type == "boolean":
        return bool
    if schema_type == "null":
        return type(None)
    if schema_type == "array":
        item_type = _json_schema_to_runtime_annotation(schema.get("items", {}))
        try:
            return list[item_type]
        except TypeError:
            return list
    if schema_type == "object":
        return dict

    return AnyType


def _create_ida_tool_wrapper(tool_def: ToolDef):
    """Create wrapper function for IDA tool"""
    from typing import Annotated, Any as AnyType, Optional as OptionalType

    def wrapper(**kwargs):
        pass

    wrapper.__name__ = tool_def.name
    wrapper.__doc__ = tool_def.description

    annotations = {}
    # _instance as first parameter: select which IDA instance to target
    annotations["_instance"] = Annotated[
        OptionalType[str],
        "Target IDA instance ID (e.g. 'ida-86893'). If omitted, uses the current active instance."
    ]

    input_schema = _build_ida_tool_input_schema(tool_def)
    schema_props = input_schema.get("properties", {})

    # Keep runtime hints aligned with parser-derived schema for hosts that
    # inspect annotations directly (instead of tools/list inputSchema).
    for param in tool_def.params:
        runtime_type = _json_schema_to_runtime_annotation(schema_props.get(param.name, {}))
        annotations[param.name] = Annotated[runtime_type, param.description]
    annotations["return"] = AnyType

    # tools/list uses this parser-derived schema as canonical source of truth.
    wrapper.__mcp_input_schema__ = input_schema
    wrapper.__annotations__ = annotations

    # Build an explicit signature so optional parameters are not incorrectly
    # marked as required by schema generation.
    signature_params = [
        inspect.Parameter(
            "_instance",
            kind=inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=annotations["_instance"],
        )
    ]
    for param in tool_def.params:
        default = inspect.Parameter.empty if param.required else param.default
        signature_params.append(
            inspect.Parameter(
                param.name,
                kind=inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=annotations[param.name],
            )
        )
    wrapper.__signature__ = inspect.Signature(
        parameters=signature_params,
        return_annotation=AnyType,
    )

    return wrapper


def _register_ida_tools(enable_unsafe: bool = False):
    """Register all IDA tools with the MCP server"""
    global IDA_TOOLS, _UNSAFE_ENABLED
    _UNSAFE_ENABLED = enable_unsafe
    
    registered_count = 0
    skipped_unsafe = 0
    
    for tool_def in _IDA_TOOLS:
        if tool_def.is_unsafe and not enable_unsafe:
            skipped_unsafe += 1
            continue
        
        IDA_TOOLS.add(tool_def.name)
        mcp.tools.methods[tool_def.name] = _create_ida_tool_wrapper(tool_def)
        registered_count += 1
    
    if skipped_unsafe > 0:
        print(f"[MCP] Registered {registered_count} IDA tools (skipped {skipped_unsafe} unsafe tools)", file=sys.stderr)
    else:
        print(f"[MCP] Registered {registered_count} IDA tools", file=sys.stderr)


def _register_ida_resources():
    """Register all IDA resources with the MCP server"""
    for res_def in _IDA_RESOURCES:
        def make_wrapper(uri):
            def wrapper(**kwargs):
                pass
            wrapper.__name__ = res_def.name
            wrapper.__doc__ = res_def.description
            setattr(wrapper, "__resource_uri__", uri)
            return wrapper
        
        mcp.resources.methods[res_def.name] = make_wrapper(res_def.uri)
    
    print(f"[MCP] Registered {len(_IDA_RESOURCES)} IDA resources", file=sys.stderr)


# ============================================================================
# Request routing
# ============================================================================

def route_to_ida(request: dict, instance_id: Optional[str] = None) -> Optional[dict]:
    """Route request to an IDA instance (via Broker).

    If instance_id is provided, route to that specific instance.
    Otherwise, route to the current active instance.
    """
    if not _broker().has_instances():
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "No active IDA instance. Please start IDA and press Ctrl+Alt+M to connect.",
            },
            "id": request.get("id"),
        }
    if instance_id is None:
        current = _broker().get_current()
        instance_id = (current or {}).get("instance_id") if current and not current.get("error") else None
    response = _broker().send_request(request, instance_id)
    if response is None:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32003, "message": "Broker request failed or timed out"},
            "id": request.get("id"),
        }
    return response


def _extract_instance_id(request: dict) -> Optional[str]:
    """Extract and remove _instance from tool call arguments.

    Returns the instance_id if found, None otherwise.
    The _instance key is removed from the request so IDA doesn't see it.
    """
    params = request.get("params", {})
    if not isinstance(params, dict):
        return None
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        return None
    return arguments.pop("_instance", None)


def _extract_resource_instance(request: dict) -> Optional[str]:
    """Extract ?instance=xxx from resource URI and strip it before forwarding.

    Returns the instance_id if found, None otherwise.
    The instance query parameter is removed from the URI so IDA sees the clean URI.
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    params = request.get("params", {})
    if not isinstance(params, dict):
        return None
    uri = params.get("uri", "")
    if not uri or "?" not in uri:
        return None

    parsed = urlparse(uri)
    qs = parse_qs(parsed.query)
    instance_id = qs.pop("instance", [None])[0]
    if instance_id:
        # Rebuild URI without the instance parameter
        new_query = urlencode({k: v[0] for k, v in qs.items()}) if qs else ""
        params["uri"] = urlunparse(parsed._replace(query=new_query))
    return instance_id


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Proxy dispatch, routes requests to IDA or handles locally"""
    if not isinstance(request, dict):
        request = json.loads(request)

    method = request.get("method", "")

    # Local protocol methods
    if method in {"initialize", "ping"} or method.startswith("notifications/"):
        return dispatch_original(request)

    # tools/call - determine if it's an IDA tool
    if method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name", "") if isinstance(params, dict) else ""

        if tool_name in IDA_TOOLS:
            # Extract optional _instance parameter before forwarding
            target_instance = _extract_instance_id(request)
            return route_to_ida(request, instance_id=target_instance)

        return dispatch_original(request)
    
    # tools/list - return all tools
    if method == "tools/list":
        response = dispatch_original(request)
        tools = response.get("result", {}).get("tools", []) if response else []
        current = _broker().get_current()
        if current and not current.get("error"):
            print(f"[MCP] tools/list: {len(tools)} tools (IDA: {current.get('name', '')})", file=sys.stderr)
        else:
            print(f"[MCP] tools/list: {len(tools)} tools (waiting for IDA connection)", file=sys.stderr)
        return response
    
    # resources related
    if method == "resources/list":
        return dispatch_original(request)
    if method == "resources/subscribe":
        return dispatch_original(request)
    if method == "resources/unsubscribe":
        return dispatch_original(request)
    if method == "resources/templates/list":
        response = dispatch_original(request)
        if response and "result" in response:
            result = response["result"]
            templates = result.get("resourceTemplates", [])
            # Append {?instance} to existing templates (RFC 6570)
            for t in templates:
                uri = t.get("uriTemplate", "")
                if "{?instance}" not in uri:
                    t["uriTemplate"] = uri + "{?instance}"
            # Add instance-aware templates for static resources
            list_resp = dispatch_original(
                {"jsonrpc": "2.0", "method": "resources/list", "id": None}
            )
            if list_resp and "result" in list_resp:
                for res in list_resp["result"].get("resources", []):
                    templates.append({
                        "uriTemplate": res["uri"] + "{?instance}",
                        "name": res["name"],
                        "description": res.get("description", ""),
                        "mimeType": res.get("mimeType", "application/json"),
                    })
            result["resourceTemplates"] = templates
        return response
    if method == "resources/read":
        if not _broker().has_instances():
            return {"jsonrpc": "2.0", "result": {"contents": []}, "id": request.get("id")}
        # Extract optional ?instance=xxx from URI before forwarding (RFC 6570)
        target_instance = _extract_resource_instance(request)
        return route_to_ida(request, instance_id=target_instance)
    
    # prompts related
    if method in {"prompts/list", "prompts/get"}:
        return dispatch_original(request)
    
    # Forward other requests to IDA
    return route_to_ida(request)


mcp.registry.dispatch = dispatch_proxy


def _is_broker_alive(broker_url: str) -> bool:
    """Check if broker is reachable by probing its TCP port."""
    from urllib.parse import urlparse
    parsed = urlparse(broker_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 13337
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _ensure_broker(broker_url: str, port: int):
    """Auto-start broker if not already running."""
    from urllib.parse import urlparse

    parsed = urlparse(broker_url)
    broker_port = parsed.port or port

    if _is_broker_alive(broker_url):
        print("[MCP] Broker already running", file=sys.stderr)
        return

    print("[MCP] Broker not detected, auto-starting...", file=sys.stderr)
    server_script = os.path.realpath(__file__)
    subprocess.Popen(
        [sys.executable, server_script, "--broker", "--port", str(broker_port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Wait for broker to become ready
    for _ in range(20):
        time.sleep(0.25)
        if _is_broker_alive(broker_url):
            print("[MCP] Broker auto-started on port", broker_port, file=sys.stderr)
            return
    print("[MCP] WARNING: Broker failed to start within 5s", file=sys.stderr)


def main():
    global HTTP_SERVER, _stdio_stdout, _broker_client

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="Install IDA plugin and MCP client configuration")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall IDA plugin and MCP client configuration")
    parser.add_argument("--allow-ida-free", action="store_true", help="Allow installation for IDA Free")
    parser.add_argument("--config", action="store_true", help="Print MCP configuration")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe tools (debugger-related)")
    parser.add_argument("--port", type=int, default=13337, help="HTTP server port (Broker mode)")
    parser.add_argument("--broker", action="store_true", help="Only start Broker (HTTP), no stdio; run separately first for multi-window/multi-IDA setups")
    parser.add_argument("--broker-url", type=str, default="http://127.0.0.1:13337", help="Broker URL for MCP mode connection")
    args = parser.parse_args()

    # Register tools
    _register_ida_tools(enable_unsafe=args.unsafe)
    _register_ida_resources()

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    if args.broker:
        # Broker mode: only start HTTP, hold REGISTRY, block main thread
        HTTP_SERVER = IDAHttpServer(port=args.port)
        HTTP_SERVER.start()
        print("[MCP] Broker started, press Ctrl+C to stop", file=sys.stderr)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            if HTTP_SERVER:
                HTTP_SERVER.stop()
        return

    # MCP mode: do not start HTTP, requests go through Broker client
    # Auto-start broker if not already running
    _ensure_broker(args.broker_url, args.port)
    _broker_client = BrokerClient(args.broker_url, timeout=10.0)

    try:
        _stdio_stdout = sys.stdout.buffer
        mcp.stdio()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("[MCP] Shutting down...", file=sys.stderr)
        _stdio_stdout = None
        os._exit(0)


if __name__ == "__main__":
    main()
