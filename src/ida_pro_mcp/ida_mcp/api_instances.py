"""IDA instance management API - HTTP+SSE version.

This module provides communication between IDA instances and the MCP server:
- Register to MCP server via HTTP
- Receive MCP requests via SSE
- Retry connections automatically

Note: These APIs run only on the IDA side for MCP server communication.
"""

import json
import os
import socket
import threading
import time
import urllib.request
import urllib.error
from typing import Callable, Optional

from .zeromcp.jsonrpc import mcp_log

# ============================================================================
# Configuration
# ============================================================================

DEFAULT_SERVER_URL = "http://127.0.0.1:13337"

# Reconnect configuration
RECONNECT_INTERVAL = 3.0  # Initial reconnect interval (seconds)
RECONNECT_MAX_INTERVAL = 30.0  # Maximum reconnect interval
RECONNECT_BACKOFF = 2.0  # Backoff multiplier


# ============================================================================
# Global state
# ============================================================================

_server_url: str = DEFAULT_SERVER_URL
_client_id: Optional[str] = None
_instance_id: Optional[str] = None
_connected = False
_running = False

_sse_thread: Optional[threading.Thread] = None
_on_mcp_request: Optional[Callable[[dict], dict]] = None

_auto_reconnect = True
_reconnect_attempt = 0
_reconnect_timer: Optional[threading.Timer] = None
_last_connect_params: Optional[dict] = None
# Protects all mutable global state above
_state_lock = threading.Lock()
_connect_lock = threading.Lock()


# ============================================================================
# HTTP helper functions
# ============================================================================

def _http_post(url: str, data: dict, timeout: float = 3.0, silent: bool = False) -> Optional[dict]:
    """Send an HTTP POST request.
    
    Args:
        url: Request URL
        data: Request payload
        timeout: Timeout in seconds, default 3 seconds
        silent: Silent mode (do not print errors)
    """
    try:
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        if not silent:
            mcp_log(f"HTTP POST failed {url}: {e}")
        return None


def _parse_sse_line(line: str) -> tuple[Optional[str], Optional[str]]:
    """Parse an SSE line and return (field, value)."""
    if not line or line.startswith(":"):
        return None, None
    if ":" in line:
        field, value = line.split(":", 1)
        return field.strip(), value.strip()
    return line, ""


# ============================================================================
# Instance ID generation
# ============================================================================

def _get_lan_ip() -> str:
    """Get LAN IP address. Returns 127.0.0.1 if no network available."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        if s:
            s.close()


def generate_instance_id() -> str:
    """Generate instance ID: ida-{PID}-[{IP}] to avoid collisions across machines."""
    return f"ida-{os.getpid()}-[{_get_lan_ip()}]"


# ============================================================================
# Connection management
# ============================================================================

def connect_to_server(
    instance_id: str = "",
    instance_type: str = "gui",
    name: str = "",
    binary_path: str = "",
    arch_info: Optional[dict] = None,
    on_mcp_request: Optional[Callable[[dict], dict]] = None,
    server_url: Optional[str] = None,
) -> bool:
    """Connect to MCP server.

    Args:
        instance_id: Unique instance ID
        instance_type: Instance type (gui/headless)
        name: Display name
        binary_path: Path of currently opened binary
        arch_info: Architecture information
        on_mcp_request: MCP request handler callback
        server_url: MCP server URL

    Returns:
        Whether connection succeeded
    """
    global _server_url, _client_id, _instance_id, _connected, _running
    global _sse_thread, _on_mcp_request, _last_connect_params, _reconnect_attempt

    if not instance_id:
        instance_id = generate_instance_id()

    with _connect_lock:
        with _state_lock:
            # Save connection parameters for reconnection
            _last_connect_params = {
                "instance_id": instance_id,
                "instance_type": instance_type,
                "name": name,
                "binary_path": binary_path,
                "arch_info": arch_info,
                "on_mcp_request": on_mcp_request,
                "server_url": server_url,
            }

            _on_mcp_request = on_mcp_request
            _server_url = server_url or DEFAULT_SERVER_URL

            # If already connected, disconnect first
            if _connected:
                _running = False
                _connected = False

            server_url = _server_url
            silent = _reconnect_attempt > 0

        # Send register request (outside _state_lock to avoid blocking)
        register_data = {
            "instance_id": instance_id,
            "instance_type": instance_type,
            "name": name,
            "binary_path": binary_path,
            "arch_info": arch_info or {},
        }

        result = _http_post(f"{server_url}/register", register_data, silent=silent)
        if not result or not result.get("success"):
            if not silent:
                mcp_log("Connection failed, waiting for Cursor to start for automatic reconnect...")
            _schedule_reconnect()
            return False

        with _state_lock:
            _client_id = result.get("client_id")
            _instance_id = instance_id
            _connected = True
            _running = True
            _reconnect_attempt = 0

        # Set instance_id in rpc module so output download URLs include it
        from .rpc import set_instance_id
        set_instance_id(instance_id)

        # Start SSE listener thread
        _sse_thread = threading.Thread(target=_sse_loop, daemon=True)
        _sse_thread.start()

        return True


def _sse_loop():
    """SSE event loop."""
    global _connected, _running

    with _state_lock:
        url = f"{_server_url}/events?client_id={_client_id}"

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=None) as resp:
            event_type = None
            event_data = ""

            for line_bytes in resp:
                if not _running:
                    break

                line = line_bytes.decode("utf-8").rstrip("\r\n")

                if not line:
                    # Empty line indicates end of event
                    if event_type and event_data:
                        _handle_sse_event(event_type, event_data)
                    event_type = None
                    event_data = ""
                    continue

                field, value = _parse_sse_line(line)
                if field == "event":
                    event_type = value
                elif field == "data":
                    event_data = value

    except Exception as e:
        if _running:
            mcp_log(f"SSE connection dropped: {e}")

    finally:
        with _state_lock:
            _connected = False
            should_reconnect = _running and _auto_reconnect
        if should_reconnect:
            _schedule_reconnect()


def _handle_sse_event(event_type: str, event_data: str):
    """Handle SSE event."""
    try:
        data = json.loads(event_data)
    except json.JSONDecodeError:
        return
    
    if event_type == "request":
        request_id = data.get("request_id")
        request = data.get("request")
        
        if request_id and request and _on_mcp_request:
            try:
                response = _on_mcp_request(request)
                _send_response(request_id, response)
            except Exception as e:
                _send_response(request_id, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": str(e)},
                    "id": request.get("id"),
                })
    
    elif event_type == "ping":
        pass  # Heartbeat, no handling needed
    
    elif event_type == "connected":
        mcp_log("SSE connected")


def _send_response(request_id: str, response: dict):
    """Send response to server."""
    with _state_lock:
        client_id = _client_id
        server_url = _server_url
    data = {
        "client_id": client_id,
        "request_id": request_id,
        "response": response,
    }
    _http_post(f"{server_url}/response", data)


# ============================================================================
# Auto-reconnect
# ============================================================================

def _schedule_reconnect():
    """Schedule reconnect (cancels any previously scheduled timer)."""
    global _reconnect_attempt, _reconnect_timer

    with _state_lock:
        if not _auto_reconnect or not _last_connect_params:
            return

        # Cancel previous timer to avoid overlapping reconnects
        if _reconnect_timer is not None:
            _reconnect_timer.cancel()
            _reconnect_timer = None

        # Exponential backoff
        interval = min(
            RECONNECT_INTERVAL * (RECONNECT_BACKOFF ** _reconnect_attempt),
            RECONNECT_MAX_INTERVAL
        )
        _reconnect_attempt += 1

        try:
            _reconnect_timer = threading.Timer(interval, _try_reconnect)
            _reconnect_timer.daemon = True
            _reconnect_timer.start()
        except Exception:
            _reconnect_timer = None


def _try_reconnect():
    """Attempt reconnect."""
    with _state_lock:
        if _connected or not _last_connect_params:
            return
        params = dict(_last_connect_params)
    success = connect_to_server(
        instance_id=params["instance_id"],
        instance_type=params["instance_type"],
        name=params["name"],
        binary_path=params["binary_path"],
        arch_info=params.get("arch_info"),
        on_mcp_request=params["on_mcp_request"],
        server_url=params["server_url"],
    )
    
    if success:
        mcp_log(f"Reconnected successfully ({params['name']})")


def set_auto_reconnect(enabled: bool):
    """Set whether auto-reconnect is enabled."""
    global _auto_reconnect
    with _state_lock:
        _auto_reconnect = enabled


def _close_connection():
    """Close connection."""
    global _connected, _running
    with _state_lock:
        _running = False
        _connected = False


def _notify_server_disconnect():
    """Notify server about disconnect (real-time disconnect detection)."""
    with _state_lock:
        client_id = _client_id
        server_url = _server_url
    if client_id:
        try:
            _http_post(f"{server_url}/unregister", {"client_id": client_id}, timeout=2.0)
        except Exception:
            pass  # Server may already be down, ignore errors


def disconnect():
    """Disconnect (manual disconnect, no auto-reconnect)."""
    global _auto_reconnect, _reconnect_timer
    with _state_lock:
        _auto_reconnect = False
        if _reconnect_timer is not None:
            _reconnect_timer.cancel()
            _reconnect_timer = None
    _notify_server_disconnect()  # Proactively notify server
    _close_connection()


def is_connected() -> bool:
    """Check whether connected."""
    with _state_lock:
        return _connected


def get_instance_id() -> Optional[str]:
    """Get current instance ID."""
    with _state_lock:
        return _instance_id
