"""IDA HTTP+SSE Server

Listens on an HTTP port, accepts IDA plugin connections.
Uses SSE to push MCP requests to IDA.
"""

import json
import queue
import socketserver
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse
import sys


@dataclass
class IDAInstance:
    """IDA instance information"""
    client_id: str
    instance_id: str
    instance_type: str = "gui"
    name: str = ""
    binary_path: str = ""
    arch_info: dict = field(default_factory=dict)
    connected_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        result = {
            "client_id": self.client_id,
            "instance_id": self.instance_id,
            "type": self.instance_type,
            "name": self.name,
            "binary_path": self.binary_path,
        }
        if self.arch_info:
            result["processor"] = self.arch_info.get("processor", "")
            result["bitness"] = self.arch_info.get("bitness", 0)
            result["endian"] = self.arch_info.get("endian", "")
            result["file_type"] = self.arch_info.get("file_type", "")
            result["base_addr"] = self.arch_info.get("base_addr", "")
        return result


class IDARegistry:
    """IDA instance registry"""
    
    def __init__(self):
        self._instances: dict[str, IDAInstance] = {}
        self._current_client_id: Optional[str] = None
        self._lock = threading.RLock()
        
        # SSE queues: client_id -> Queue
        self._sse_queues: dict[str, queue.Queue] = {}
        
        # Pending requests: request_id -> {event, response, client_id}
        self._pending: dict[str, dict] = {}
        
        # Callbacks
        self._on_connect: Optional[Callable[[IDAInstance], None]] = None
        self._on_disconnect: Optional[Callable[[str], None]] = None
    
    def _fail_pending_for_client(self, client_id: str):
        """Fail all pending requests belonging to a client (caller must hold _lock)."""
        to_fail = [info for info in self._pending.values() if info.get("client_id") == client_id]
        for info in to_fail:
            # Keep entry in _pending so waiter can pop and read the response.
            if info.get("response") is None:
                info["response"] = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": "IDA instance disconnected"},
                    "id": info.get("rpc_id"),
                }
            info["event"].set()

    def register(self, data: dict) -> Optional[IDAInstance]:
        """Register an IDA instance. Replaces old connection when the same instance_id reconnects, avoiding duplicates."""
        with self._lock:
            instance_id = data.get("instance_id", "")
            # Remove old connection if same instance_id already exists (caused by reconnection or duplicate clicks)
            for old_client_id, old_inst in list(self._instances.items()):
                if old_inst.instance_id == instance_id:
                    self._fail_pending_for_client(old_client_id)
                    self._instances.pop(old_client_id, None)
                    self._sse_queues.pop(old_client_id, None)
                    if self._current_client_id == old_client_id:
                        self._current_client_id = None
                    print(f"[HTTP] Replaced old connection: {old_inst.name or instance_id} ({old_client_id})", file=sys.stderr)
                    sys.stderr.flush()
                    break

            client_id = str(uuid.uuid4())[:8]
            instance = IDAInstance(
                client_id=client_id,
                instance_id=instance_id or client_id,
                instance_type=data.get("instance_type", "gui"),
                name=data.get("name", ""),
                binary_path=data.get("binary_path", ""),
                arch_info=data.get("arch_info", {}),
            )
            self._instances[client_id] = instance
            self._sse_queues[client_id] = queue.Queue()

            if self._current_client_id is None:
                self._current_client_id = client_id

            print(f"[HTTP] +++ IDA connected: {instance.name or instance.instance_id} +++", file=sys.stderr)
            sys.stderr.flush()

            if self._on_connect:
                self._on_connect(instance)

            return instance
    
    def unregister(self, client_id: str):
        """Unregister an IDA instance"""
        with self._lock:
            self._fail_pending_for_client(client_id)
            instance = self._instances.pop(client_id, None)
            self._sse_queues.pop(client_id, None)
            
            if instance:
                print(f"[HTTP] --- IDA disconnected: {instance.name or instance.instance_id} ---", file=sys.stderr)
                sys.stderr.flush()
                
                if self._on_disconnect:
                    self._on_disconnect(instance.instance_id)
            
            if self._current_client_id == client_id:
                self._current_client_id = next(iter(self._instances), None)
    
    def get_current(self) -> Optional[IDAInstance]:
        """Get current instance"""
        with self._lock:
            if self._current_client_id:
                return self._instances.get(self._current_client_id)
            return None
    
    def get_by_client_id(self, client_id: str) -> Optional[IDAInstance]:
        """Get instance by client_id"""
        with self._lock:
            return self._instances.get(client_id)
    
    def get_by_instance_id(self, instance_id: str) -> Optional[IDAInstance]:
        """Get instance by instance_id"""
        with self._lock:
            for inst in self._instances.values():
                if inst.instance_id == instance_id:
                    return inst
            return None
    
    def set_current(self, instance_id: str) -> bool:
        """Set current instance"""
        with self._lock:
            for client_id, inst in self._instances.items():
                if inst.instance_id == instance_id:
                    self._current_client_id = client_id
                    return True
            return False
    
    def list_all(self) -> list[dict]:
        """List all instances"""
        with self._lock:
            return [
                {**inst.to_dict(), "is_current": inst.client_id == self._current_client_id}
                for inst in self._instances.values()
            ]
    
    def has_instances(self) -> bool:
        """Check if there are any instances"""
        with self._lock:
            return len(self._instances) > 0
    
    def send_request(self, request: dict, instance_id: Optional[str] = None, timeout: float = 60.0) -> Optional[dict]:
        """Send request to IDA and wait for response"""
        with self._lock:
            # Determine target instance
            if instance_id:
                inst = self.get_by_instance_id(instance_id)
            else:
                inst = self.get_current()
            
            if not inst:
                return None
            
            client_id = inst.client_id
            sse_queue = self._sse_queues.get(client_id)
            if not sse_queue:
                return None
            
            # Create request tracking
            request_id = str(uuid.uuid4())[:8]
            event = threading.Event()
            self._pending[request_id] = {
                "event": event,
                "response": None,
                "client_id": client_id,
                "rpc_id": request.get("id"),
            }
        
        # Put into SSE queue
        sse_queue.put({"request_id": request_id, "request": request})
        
        # Wait for response
        if event.wait(timeout):
            with self._lock:
                result = self._pending.pop(request_id, {})
                return result.get("response")
        else:
            with self._lock:
                self._pending.pop(request_id, None)
            return None
    
    def set_response(self, request_id: str, response: dict):
        """Set request response"""
        with self._lock:
            info = self._pending.get(request_id)
            # Keep first terminal state to avoid races with disconnect handling.
            if info is not None and info.get("response") is None:
                info["response"] = response
                info["event"].set()
    
    def get_sse_queue(self, client_id: str) -> Optional[queue.Queue]:
        """Get SSE queue"""
        with self._lock:
            return self._sse_queues.get(client_id)


# Global registry
REGISTRY = IDARegistry()


class IDARequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler"""
    
    def log_message(self, format, *args):
        """Redirect logs to stderr"""
        print(f"[HTTP] {args[0]}", file=sys.stderr)
        sys.stderr.flush()
    
    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response"""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
    
    def _read_json(self) -> Optional[dict]:
        """Read JSON request body"""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            body = self.rfile.read(length)
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def do_POST(self):
        """Handle POST requests"""
        path = urlparse(self.path).path
        
        if path == "/register":
            self._handle_register()
        elif path == "/unregister":
            self._handle_unregister()
        elif path == "/response":
            self._handle_response()
        elif path == "/api/current":
            self._handle_api_current_set()
        elif path == "/api/request":
            self._handle_api_request()
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        if path == "/" or path == "/index.html":
            self._serve_dashboard()
        elif path == "/events":
            client_id = params.get("client_id", [None])[0]
            if client_id:
                self._handle_sse(client_id)
            else:
                self._send_json({"error": "Missing client_id"}, 400)
        elif path == "/status":
            self._send_json({"instances": REGISTRY.list_all()})
        elif path == "/api/instances":
            self._send_json(REGISTRY.list_all())
        elif path == "/api/current":
            self._handle_api_current_get()
        elif path == "/api/ping":
            self._send_json({"status": "ok"})
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def _handle_register(self):
        """Handle IDA registration"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        instance = REGISTRY.register(data)
        if instance:
            self._send_json({"success": True, "client_id": instance.client_id})
        else:
            self._send_json({"error": "Registration failed"}, 500)
    
    def _handle_unregister(self):
        """Handle IDA voluntary disconnect"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        client_id = data.get("client_id")
        if client_id:
            REGISTRY.unregister(client_id)
            self._send_json({"success": True})
        else:
            self._send_json({"error": "Missing client_id"}, 400)
    
    def _handle_response(self):
        """Handle IDA response"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        request_id = data.get("request_id")
        response = data.get("response")
        
        if request_id and response:
            REGISTRY.set_response(request_id, response)
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "Missing request_id or response"}, 400)
    
    def _handle_api_current_get(self):
        """GET /api/current - Return current instance info (for MCP client use)"""
        instance = REGISTRY.get_current()
        if instance is None:
            self._send_json({"error": "No active IDA instance. Please start IDA and press Ctrl+Alt+M to connect."})
            return
        self._send_json({**instance.to_dict(), "is_current": True})
    
    def _handle_api_current_set(self):
        """POST /api/current - Set current instance (for MCP client use)"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        instance_id = data.get("instance_id")
        if not instance_id:
            self._send_json({"success": False, "error": "Missing instance_id"}, 400)
            return
        if REGISTRY.set_current(instance_id):
            instance = REGISTRY.get_by_instance_id(instance_id)
            self._send_json({
                "success": True,
                "message": f"Switched to instance: {instance_id}",
                "instance": instance.to_dict() if instance else None,
            })
        else:
            self._send_json({"success": False, "error": f"Instance not found: {instance_id}"})
    
    def _handle_api_request(self):
        """POST /api/request - Forward MCP request to IDA and return response (for MCP client use)"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        request = data.get("request")
        instance_id = data.get("instance_id")
        timeout_raw = data.get("timeout", 60.0)
        try:
            timeout = float(timeout_raw)
        except (TypeError, ValueError):
            self._send_json(
                {
                    "ok": False,
                    "error_code": "invalid_timeout",
                    "error": "Invalid timeout value",
                    "response": None,
                },
                400,
            )
            return
        if not request:
            self._send_json(
                {
                    "ok": False,
                    "error_code": "missing_request",
                    "error": "Missing request",
                    "response": None,
                },
                400,
            )
            return
        if timeout <= 0:
            self._send_json(
                {
                    "ok": False,
                    "error_code": "invalid_timeout",
                    "error": "Timeout must be greater than 0",
                    "response": None,
                },
                400,
            )
            return

        if instance_id:
            if REGISTRY.get_by_instance_id(instance_id) is None:
                self._send_json(
                    {
                        "ok": False,
                        "error_code": "instance_not_found",
                        "error": f"Instance not found: {instance_id}",
                        "response": None,
                    },
                    404,
                )
                return
        elif REGISTRY.get_current() is None:
            self._send_json(
                {
                    "ok": False,
                    "error_code": "no_active_instance",
                    "error": "No active IDA instance. Please start IDA and press Ctrl+Alt+M to connect.",
                    "response": None,
                },
                503,
            )
            return

        response = REGISTRY.send_request(request, instance_id, timeout=timeout)
        if response is None:
            self._send_json(
                {
                    "ok": False,
                    "error_code": "timeout",
                    "error": "IDA request timed out",
                    "response": None,
                },
                504,
            )
            return

        self._send_json({"ok": True, "response": response})
    
    def _handle_sse(self, client_id: str):
        """Handle SSE connection"""
        instance = REGISTRY.get_by_client_id(client_id)
        if not instance:
            self._send_json({"error": "Unknown client_id"}, 404)
            return
        
        sse_queue = REGISTRY.get_sse_queue(client_id)
        if not sse_queue:
            self._send_json({"error": "No queue"}, 500)
            return
        
        # Send SSE headers
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        
        # Send connection success event
        self._send_sse_event("connected", {"client_id": client_id})
        
        try:
            while True:
                try:
                    # Send heartbeat every 10 seconds to check connection state
                    # Note: heartbeat is one-way; it fails only when TCP disconnects (process exits)
                    # If IDA main thread is stuck, TCP may still be connected and should not be treated as disconnect
                    item = sse_queue.get(timeout=10)
                    self._send_sse_event("request", item)
                except queue.Empty:
                    # Send heartbeat; write failure triggers BrokenPipeError
                    self._send_sse_event("ping", {})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            # Unregister on disconnect
            REGISTRY.unregister(client_id)
    
    def _send_sse_event(self, event: str, data: dict):
        """Send an SSE event."""
        msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        self.wfile.write(msg.encode("utf-8"))
        self.wfile.flush()

    @staticmethod
    def _esc(s: str) -> str:
        """Escape HTML special characters."""
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")

    def _serve_dashboard(self):
        """Serve the web dashboard HTML page."""
        instances = REGISTRY.list_all()

        instance_rows = ""
        for inst in instances:
            esc = self._esc
            iid = esc(inst.get('instance_id', ''))
            current = '<span class="badge">Current</span>' if inst.get("is_current") else ""
            proc = esc(inst.get("processor", ""))
            bits = inst.get("bitness", "")
            arch = f"{proc}/{bits}" if proc else "-"
            name = esc(inst.get('name', '') or '-')
            bpath = esc(inst.get('binary_path', ''))
            bpath_short = esc(inst.get('binary_path', '')[-50:]) or '-'

            instance_rows += f"""
            <tr>
                <td><code>{iid}</code> {current}</td>
                <td>{esc(inst.get('type', 'gui'))}</td>
                <td>{name}</td>
                <td>{arch}</td>
                <td title="{bpath}">{bpath_short}</td>
                <td>
                    <button onclick="switchTo('{iid}')" class="btn btn-primary">Switch</button>
                </td>
            </tr>"""

        if not instances:
            instance_rows = '<tr><td colspan="6" class="empty">No IDA instances connected. Start IDA and press Ctrl+Alt+M.</td></tr>'

        html = f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><title>IDA MCP Broker</title>
<style>
:root {{ --bg:#fff; --text:#1a1a1a; --border:#ddd; --primary:#0066cc; --success:#28a745; --danger:#dc3545; }}
@media(prefers-color-scheme:dark) {{ :root {{ --bg:#1a1a1a; --text:#e0e0e0; --border:#333; --primary:#4da6ff; --success:#4caf50; --danger:#f44336; }} }}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ font-family:system-ui,sans-serif; background:var(--bg); color:var(--text); padding:2rem; max-width:1200px; margin:auto; }}
h1 {{ margin-bottom:1.5rem; }}
table {{ width:100%; border-collapse:collapse; background:var(--bg); border:1px solid var(--border); }}
th,td {{ padding:.75rem; text-align:left; border-bottom:1px solid var(--border); }}
th {{ background:var(--border); }}
.badge {{ background:var(--primary); color:#fff; padding:.125rem .375rem; border-radius:4px; font-size:.625rem; margin-left:.5rem; }}
.btn {{ padding:.375rem .75rem; border:1px solid var(--border); border-radius:4px; background:var(--bg); color:var(--text); cursor:pointer; text-decoration:none; font-size:.875rem; }}
.btn-primary {{ background:var(--primary); color:#fff; border-color:var(--primary); }}
.btn-primary:hover {{ opacity:.85; }}
.empty {{ text-align:center; color:#888; padding:2rem!important; }}
a {{ color:var(--primary); }}
code {{ background:var(--border); padding:.125rem .25rem; border-radius:3px; font-size:.8rem; }}
.footer {{ margin-top:2rem; color:#888; font-size:.75rem; }}
.count {{ color:#888; font-size:.9rem; font-weight:normal; margin-left:.5rem; }}
</style>
</head><body>
<h1>IDA MCP Broker <span class="count">({len(instances)} instance{"s" if len(instances) != 1 else ""})</span></h1>
<table>
<thead><tr><th>Instance</th><th>Type</th><th>Name</th><th>Arch</th><th>Binary</th><th>Actions</th></tr></thead>
<tbody>{instance_rows}</tbody>
</table>
<div class="footer">
<p>Localhost only | HTTP+SSE | Auto-refresh 10s</p>
<p style="margin-top:.5rem"><code>GET /api/instances</code> <code>GET /api/current</code> <code>POST /api/request</code></p>
</div>
<script>
function switchTo(id) {{
    fetch('/api/current', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{instance_id:id}}) }})
    .then(r => r.json()).then(d => {{ if(d.success) location.reload(); else alert(d.error || 'Switch failed'); }});
}}
setTimeout(() => location.reload(), 10000);
</script>
</body></html>"""

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Multithreaded HTTP server: handle each request (including long-lived SSE) in its own thread."""
    daemon_threads = True


class IDAHttpServer:
    """IDA HTTP+SSE server."""

    def __init__(self, port: int = 13337):
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start server."""
        if self._running:
            return

        try:
            self._server = ThreadedHTTPServer(("127.0.0.1", self.port), IDARequestHandler)
            self._server.timeout = 1
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()

            print(f"[HTTP] Server started (multithreaded): http://127.0.0.1:{self.port}", file=sys.stderr)
            sys.stderr.flush()
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"[HTTP] Port {self.port} is already in use, skipping HTTP server startup", file=sys.stderr)
                sys.stderr.flush()
            else:
                raise

    def _serve(self):
        """Serve loop (each accepted connection is dispatched to a new thread)."""
        while self._running:
            try:
                self._server.handle_request()
            except Exception:
                if self._running:
                    pass
    
    def stop(self):
        """Stop server."""
        self._running = False
        if self._server:
            try:
                self._server.server_close()
            except Exception:
                pass
            self._server = None
    
    @property
    def registry(self) -> IDARegistry:
        """Get registry."""
        return REGISTRY
