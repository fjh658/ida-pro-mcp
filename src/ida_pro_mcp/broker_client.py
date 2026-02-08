"""Broker HTTP client.

MCP processes use this module to query the Broker
(instance list, current instance, forwarded IDA requests).
"""

import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Optional

# TTL for has_instances cache (seconds)
_HAS_INSTANCES_TTL = 2.0


class BrokerClient:
    """Broker HTTP client."""

    def __init__(self, base_url: str = "http://127.0.0.1:13337", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._has_instances_cache: Optional[bool] = None
        self._has_instances_ts: float = 0.0

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[dict] = None,
        timeout: Optional[float] = None,
    ) -> Optional[dict]:
        url = f"{self.base_url}{path}"
        timeout = timeout if timeout is not None else self.timeout
        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"} if body else {},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            # Read error response body (broker returns JSON with error details)
            try:
                raw = e.read().decode("utf-8")
                return json.loads(raw) if raw else None
            except Exception:
                print(f"[MCP] Broker HTTP {e.code} {path}: {e}", file=sys.stderr)
                return None
        except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError) as e:
            print(f"[MCP] Broker request failed {path}: {e}", file=sys.stderr)
            return None

    def list_instances(self) -> list[dict]:
        """GET /api/instances"""
        out = self._request("GET", "/api/instances")
        return out if isinstance(out, list) else []

    def get_current(self) -> Optional[dict]:
        """GET /api/current"""
        return self._request("GET", "/api/current")

    def set_current(self, instance_id: str) -> dict:
        """POST /api/current"""
        out = self._request("POST", "/api/current", {"instance_id": instance_id})
        return out if isinstance(out, dict) else {"success": False, "error": "No response from Broker"}

    def send_request(
        self,
        request: dict,
        instance_id: Optional[str] = None,
        timeout: float = 60.0,
    ) -> Optional[dict]:
        """POST /api/request, return IDA response."""
        def jsonrpc_error(code: int, message: str, error_code: str) -> dict:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": code,
                    "message": message,
                    "data": {"error_code": error_code},
                },
                "id": request.get("id"),
            }

        payload = {"request": request, "timeout": timeout}
        if instance_id is not None:
            payload["instance_id"] = instance_id
        out = self._request("POST", "/api/request", payload, timeout=timeout + 5)
        if out is None:
            return jsonrpc_error(-32003, "Broker unavailable or request failed", "broker_unavailable")

        # Backward compatibility with old Broker response format.
        if "ok" not in out and "response" in out:
            return out.get("response")

        if out.get("ok") is True:
            response = out.get("response")
            if isinstance(response, dict):
                return response
            return jsonrpc_error(-32003, "Broker returned invalid response payload", "invalid_response")

        error_code = str(out.get("error_code") or "broker_error")
        message = str(out.get("error") or "Broker request failed")
        code_map = {
            "instance_not_found": -32004,
            "no_active_instance": -32000,
            "timeout": -32002,
            "invalid_timeout": -32602,
            "missing_request": -32600,
            "broker_error": -32003,
        }
        return jsonrpc_error(code_map.get(error_code, -32003), message, error_code)

    def has_instances(self) -> bool:
        """Return whether any instances are connected (cached for 2s)."""
        now = time.monotonic()
        if self._has_instances_cache is not None and (now - self._has_instances_ts) < _HAS_INSTANCES_TTL:
            return self._has_instances_cache
        result = len(self.list_instances()) > 0
        self._has_instances_cache = result
        self._has_instances_ts = now
        return result
