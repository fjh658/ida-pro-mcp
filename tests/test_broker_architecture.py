import pathlib
import sys
import threading
import time
import unittest
from typing import TypedDict
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
ZEROMCP_DIR = SRC / "ida_pro_mcp" / "ida_mcp" / "zeromcp"
if str(ZEROMCP_DIR) not in sys.path:
    sys.path.insert(0, str(ZEROMCP_DIR))

import ida_pro_mcp.http_server as http_server_module
import ida_pro_mcp.server as server_module
from ida_pro_mcp.broker_client import BrokerClient
from ida_pro_mcp.http_server import IDARegistry
from ida_pro_mcp.server import _create_ida_tool_wrapper, mcp
from ida_pro_mcp.tool_registry import ToolDef, ToolParam, type_str_to_json_schema
from jsonrpc import JsonRpcRegistry


class ToolSchemaRequiredTests(unittest.TestCase):
    def test_dynamic_wrapper_marks_only_true_required_fields(self):
        # Regression guard: wrapper-injected broker routing arg `_instance`
        # must stay optional, while true tool params follow parsed requiredness.
        tool_def = ToolDef(
            name="demo_tool",
            description="demo",
            params=[
                ToolParam(name="addr", type_str="str", description="address", required=True),
                ToolParam(
                    name="offset",
                    type_str="int",
                    description="optional offset",
                    required=False,
                    default=0,
                ),
                ToolParam(
                    name="include_total",
                    type_str="bool",
                    description="optional switch",
                    required=False,
                    default=None,
                ),
            ],
        )
        wrapper = _create_ida_tool_wrapper(tool_def)
        schema = mcp._generate_tool_schema(tool_def.name, wrapper)

        required = set(schema["inputSchema"].get("required", []))
        properties = schema["inputSchema"]["properties"]

        self.assertIn("_instance", properties)
        self.assertNotIn("_instance", required)
        self.assertIn("addr", required)
        self.assertNotIn("offset", required)
        self.assertNotIn("include_total", required)

    def test_dynamic_wrapper_preserves_declared_param_types(self):
        # Regression guard for the original Any->object type-loss bug:
        # parser-declared union/list/int/bool must survive tools/list schema.
        tool_def = ToolDef(
            name="typed_demo_tool",
            description="typed demo",
            params=[
                ToolParam(name="queries", type_str="list[str] | str", description="query list", required=True),
                ToolParam(name="limit", type_str="int", description="limit", required=False, default=100),
                ToolParam(name="include_total", type_str="bool", description="switch", required=False, default=False),
            ],
        )
        wrapper = _create_ida_tool_wrapper(tool_def)
        schema = mcp._generate_tool_schema(tool_def.name, wrapper)

        required = set(schema["inputSchema"].get("required", []))
        properties = schema["inputSchema"]["properties"]

        self.assertIn("_instance", properties)
        self.assertIn("anyOf", properties["_instance"])
        self.assertIn("anyOf", properties["queries"])
        query_variants = properties["queries"]["anyOf"]
        self.assertIn({"type": "string"}, query_variants)
        self.assertIn({"type": "array", "items": {"type": "string"}}, query_variants)
        self.assertEqual(properties["limit"]["type"], "integer")
        self.assertEqual(properties["include_total"]["type"], "boolean")
        self.assertEqual(properties["limit"]["default"], 100)
        self.assertEqual(properties["include_total"]["default"], False)

        self.assertIn("queries", required)
        self.assertNotIn("_instance", required)
        self.assertNotIn("limit", required)
        self.assertNotIn("include_total", required)


class TypeParserTypedDictTests(unittest.TestCase):
    def test_typeddict_is_expanded_for_union_and_list(self):
        # Ensure TypedDict symbols are expanded into structured object schemas
        # both as single values and inside list/union branches.
        schema = type_str_to_json_schema("list[MemoryRead] | MemoryRead")
        self.assertIn("anyOf", schema)

        variants = schema["anyOf"]
        obj_variant = next(v for v in variants if v.get("type") == "object")
        arr_variant = next(v for v in variants if v.get("type") == "array")

        self.assertEqual(obj_variant["properties"]["addr"]["type"], "string")
        self.assertEqual(obj_variant["properties"]["size"]["type"], "integer")
        self.assertEqual(set(obj_variant.get("required", [])), {"addr", "size"})

        items_schema = arr_variant["items"]
        self.assertEqual(items_schema["type"], "object")
        self.assertEqual(items_schema["properties"]["addr"]["type"], "string")
        self.assertEqual(items_schema["properties"]["size"]["type"], "integer")
        self.assertEqual(set(items_schema.get("required", [])), {"addr", "size"})

    def test_typeddict_total_false_keeps_fields_optional(self):
        # total=False TypedDict fields are optional by definition and should not
        # be emitted as schema-level required properties.
        schema = type_str_to_json_schema("ListQuery")
        self.assertEqual(schema["type"], "object")
        self.assertEqual(set(schema["properties"].keys()), {"filter", "offset", "count"})
        self.assertNotIn("required", schema)


class DisconnectPendingRequestTests(unittest.TestCase):
    def test_unregister_returns_disconnected_error_for_pending_request(self):
        registry = IDARegistry()
        instance = registry.register({"instance_id": "ida-1", "name": "test"})
        self.assertIsNotNone(instance)
        assert instance is not None

        out: dict[str, object] = {}

        def worker():
            out["response"] = registry.send_request(
                {"jsonrpc": "2.0", "id": 4242, "method": "tools/list"},
                timeout=5.0,
            )

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        # Wait until request is queued in pending map.
        for _ in range(100):
            with registry._lock:  # Test-only introspection for deterministic timing.
                if registry._pending:
                    break
            time.sleep(0.01)

        registry.unregister(instance.client_id)
        thread.join(timeout=1.5)

        self.assertFalse(thread.is_alive(), "worker thread should be released on unregister")
        response = out.get("response")
        self.assertIsInstance(response, dict)
        assert isinstance(response, dict)
        self.assertEqual(response.get("id"), 4242)
        self.assertEqual(response.get("error", {}).get("message"), "IDA instance disconnected")


class BrokerErrorMappingTests(unittest.TestCase):
    @staticmethod
    def _call_with_broker_payload(payload):
        client = BrokerClient()
        client._request = lambda *args, **kwargs: payload
        return client.send_request({"jsonrpc": "2.0", "id": 99, "method": "tools/call"})

    def test_maps_broker_unavailable(self):
        result = self._call_with_broker_payload(None)
        self.assertEqual(result["error"]["code"], -32003)
        self.assertEqual(result["error"]["data"]["error_code"], "broker_unavailable")

    def test_maps_instance_not_found(self):
        payload = {
            "ok": False,
            "error_code": "instance_not_found",
            "error": "Instance not found: ida-x",
            "response": None,
        }
        result = self._call_with_broker_payload(payload)
        self.assertEqual(result["error"]["code"], -32004)
        self.assertEqual(result["error"]["data"]["error_code"], "instance_not_found")

    def test_maps_no_active_instance(self):
        payload = {
            "ok": False,
            "error_code": "no_active_instance",
            "error": "No active IDA instance",
            "response": None,
        }
        result = self._call_with_broker_payload(payload)
        self.assertEqual(result["error"]["code"], -32000)
        self.assertEqual(result["error"]["data"]["error_code"], "no_active_instance")

    def test_maps_timeout(self):
        payload = {
            "ok": False,
            "error_code": "timeout",
            "error": "IDA request timed out",
            "response": None,
        }
        result = self._call_with_broker_payload(payload)
        self.assertEqual(result["error"]["code"], -32002)
        self.assertEqual(result["error"]["data"]["error_code"], "timeout")

    def test_accepts_success_payload(self):
        payload = {"ok": True, "response": {"jsonrpc": "2.0", "result": {"x": 1}, "id": 99}}
        result = self._call_with_broker_payload(payload)
        self.assertEqual(result["result"]["x"], 1)
        self.assertEqual(result["id"], 99)

    def test_accepts_legacy_broker_response_shape(self):
        payload = {"response": {"jsonrpc": "2.0", "result": {"legacy": True}, "id": 99}}
        result = self._call_with_broker_payload(payload)
        self.assertEqual(result["result"]["legacy"], True)
        self.assertEqual(result["id"], 99)


class DispatchProxyRoutingTests(unittest.TestCase):
    def test_resources_subscribe_and_unsubscribe_stay_local(self):
        class _FailBroker:
            def has_instances(self):
                raise AssertionError("broker should not be called for local resources subscription methods")

        request_sub = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "resources/subscribe",
            "params": {"uri": "ida://meta/current"},
        }
        request_unsub = {
            "jsonrpc": "2.0",
            "id": 102,
            "method": "resources/unsubscribe",
            "params": {"uri": "ida://meta/current"},
        }

        with patch.object(server_module, "_broker_client", _FailBroker()):
            sub_resp = server_module.dispatch_proxy(request_sub)
            unsub_resp = server_module.dispatch_proxy(request_unsub)

        self.assertEqual(sub_resp, {"jsonrpc": "2.0", "result": {}, "id": 101})
        self.assertEqual(unsub_resp, {"jsonrpc": "2.0", "result": {}, "id": 102})

    def test_ensure_broker_uses_port_from_broker_url(self):
        with patch.object(server_module, "_is_broker_alive", side_effect=[False, True]):
            with patch.object(server_module.subprocess, "Popen") as popen_mock:
                with patch.object(server_module.time, "sleep", return_value=None):
                    server_module._ensure_broker("http://127.0.0.1:18000", 13337)

        self.assertTrue(popen_mock.called)
        argv = popen_mock.call_args.args[0]
        self.assertIn("--port", argv)
        self.assertEqual(argv[argv.index("--port") + 1], "18000")


class BrokerClientRobustnessTests(unittest.TestCase):
    def test_request_handles_unexpected_os_errors(self):
        client = BrokerClient()
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}

        with patch("urllib.request.urlopen", side_effect=PermissionError("denied")):
            response = client.send_request(request)

        self.assertEqual(response["error"]["code"], -32003)
        self.assertEqual(response["error"]["data"]["error_code"], "broker_unavailable")


class HttpServerStartupTests(unittest.TestCase):
    def test_port_in_use_errno_98_is_handled_gracefully(self):
        server = http_server_module.IDAHttpServer(port=13337)
        with patch.object(http_server_module, "ThreadedHTTPServer", side_effect=OSError(98, "in use")):
            server.start()
        self.assertFalse(server._running)


class JsonRpcStrictTypeValidationTests(unittest.TestCase):
    class _Point(TypedDict):
        x: int

    @staticmethod
    def _dispatch(registry: JsonRpcRegistry, method: str, params: dict, req_id: int = 1):
        return registry.dispatch(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params,
            }
        )

    def test_rejects_string_for_int_bool_list_and_typeddict(self):
        registry = JsonRpcRegistry()

        def need_int(x: int):
            return x

        def need_bool(flag: bool):
            return flag

        def need_list(values: list[int]):
            return len(values)

        def need_point(point: JsonRpcStrictTypeValidationTests._Point):
            return point["x"]

        registry.method(need_int, "need_int")
        registry.method(need_bool, "need_bool")
        registry.method(need_list, "need_list")
        registry.method(need_point, "need_point")

        cases = [
            ("need_int", {"x": "20"}),
            ("need_bool", {"flag": "true"}),
            ("need_list", {"values": "[1,2,3]"}),
            ("need_point", {"point": '{"x":1}'}),
        ]

        for idx, (method, params) in enumerate(cases, start=1):
            response = self._dispatch(registry, method, params, req_id=idx)
            self.assertIsInstance(response, dict)
            self.assertIn("error", response)
            self.assertEqual(response["error"]["code"], -32602)

    def test_accepts_correctly_typed_params(self):
        registry = JsonRpcRegistry()

        def need_int(x: int):
            return x * 2

        registry.method(need_int, "need_int")
        response = self._dispatch(registry, "need_int", {"x": 21})
        self.assertIsInstance(response, dict)
        self.assertEqual(response.get("result"), 42)


if __name__ == "__main__":
    unittest.main()
