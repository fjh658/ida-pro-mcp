"""Tests for api_instances.py state lock and reconnect logic."""

import pathlib
import sys
import threading
import unittest
from unittest.mock import patch, MagicMock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TESTS = ROOT / "tests"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
ZEROMCP_DIR = SRC / "ida_pro_mcp" / "ida_mcp" / "zeromcp"
if str(ZEROMCP_DIR) not in sys.path:
    sys.path.insert(0, str(ZEROMCP_DIR))
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _ida_stubs import install as _install_stubs
_install_stubs()

import ida_pro_mcp.ida_mcp.api_instances as inst


def _reset_state():
    """Reset module globals to clean state."""
    with inst._state_lock:
        inst._server_url = inst.DEFAULT_SERVER_URL
        inst._client_id = None
        inst._instance_id = None
        inst._connected = False
        inst._running = False
        inst._sse_thread = None
        inst._on_mcp_request = None
        inst._auto_reconnect = True
        inst._reconnect_attempt = 0
        if inst._reconnect_timer is not None:
            inst._reconnect_timer.cancel()
        inst._reconnect_timer = None
        inst._last_connect_params = None


class StateLockTests(unittest.TestCase):

    def setUp(self):
        _reset_state()

    def tearDown(self):
        _reset_state()

    def test_is_connected_reads_under_lock(self):
        self.assertFalse(inst.is_connected())
        with inst._state_lock:
            inst._connected = True
        self.assertTrue(inst.is_connected())

    def test_get_instance_id_reads_under_lock(self):
        self.assertIsNone(inst.get_instance_id())
        with inst._state_lock:
            inst._instance_id = "test-123"
        self.assertEqual(inst.get_instance_id(), "test-123")

    def test_set_auto_reconnect(self):
        inst.set_auto_reconnect(False)
        with inst._state_lock:
            self.assertFalse(inst._auto_reconnect)
        inst.set_auto_reconnect(True)
        with inst._state_lock:
            self.assertTrue(inst._auto_reconnect)

    def test_close_connection_sets_flags(self):
        with inst._state_lock:
            inst._running = True
            inst._connected = True
        inst._close_connection()
        self.assertFalse(inst.is_connected())
        with inst._state_lock:
            self.assertFalse(inst._running)


class ScheduleReconnectTests(unittest.TestCase):

    def setUp(self):
        _reset_state()

    def tearDown(self):
        _reset_state()

    _PARAMS = {
        "instance_id": "test",
        "instance_type": "gui",
        "name": "test",
        "binary_path": "",
        "arch_info": None,
        "on_mcp_request": None,
        "server_url": None,
    }

    def test_no_reconnect_when_disabled(self):
        inst.set_auto_reconnect(False)
        with inst._state_lock:
            inst._last_connect_params = dict(self._PARAMS)
        inst._schedule_reconnect()
        with inst._state_lock:
            self.assertIsNone(inst._reconnect_timer)

    def test_no_reconnect_without_params(self):
        inst._schedule_reconnect()
        with inst._state_lock:
            self.assertIsNone(inst._reconnect_timer)

    def test_schedule_creates_timer(self):
        with inst._state_lock:
            inst._last_connect_params = dict(self._PARAMS)
        inst._schedule_reconnect()
        with inst._state_lock:
            self.assertIsNotNone(inst._reconnect_timer)
            inst._reconnect_timer.cancel()
            inst._reconnect_timer = None

    def test_schedule_cancels_previous_timer(self):
        with inst._state_lock:
            inst._last_connect_params = dict(self._PARAMS)
        inst._schedule_reconnect()
        with inst._state_lock:
            first_timer = inst._reconnect_timer

        inst._schedule_reconnect()
        with inst._state_lock:
            second_timer = inst._reconnect_timer
            if second_timer:
                second_timer.cancel()
            inst._reconnect_timer = None

        self.assertIsNot(first_timer, second_timer)

    def test_exponential_backoff_increases_attempt(self):
        with inst._state_lock:
            inst._last_connect_params = dict(self._PARAMS)
            initial_attempt = inst._reconnect_attempt

        inst._schedule_reconnect()
        with inst._state_lock:
            self.assertEqual(inst._reconnect_attempt, initial_attempt + 1)
            if inst._reconnect_timer:
                inst._reconnect_timer.cancel()
            inst._reconnect_timer = None

    def test_timer_exception_cleans_up(self):
        """If Timer creation/start fails, _reconnect_timer should be None."""
        with inst._state_lock:
            inst._last_connect_params = dict(self._PARAMS)

        with patch("threading.Timer", side_effect=RuntimeError("boom")):
            inst._schedule_reconnect()

        with inst._state_lock:
            self.assertIsNone(inst._reconnect_timer)


class DisconnectTests(unittest.TestCase):

    def setUp(self):
        _reset_state()

    def tearDown(self):
        _reset_state()

    def test_disconnect_cancels_timer_and_stops(self):
        mock_timer = MagicMock()
        with inst._state_lock:
            inst._reconnect_timer = mock_timer
            inst._auto_reconnect = True
            inst._connected = True
            inst._running = True
            inst._client_id = "test-client"

        with patch.object(inst, "_http_post"):
            inst.disconnect()

        mock_timer.cancel.assert_called_once()
        self.assertFalse(inst.is_connected())
        with inst._state_lock:
            self.assertFalse(inst._auto_reconnect)
            self.assertIsNone(inst._reconnect_timer)


class TryReconnectTests(unittest.TestCase):

    def setUp(self):
        _reset_state()

    def tearDown(self):
        _reset_state()

    def test_skip_if_already_connected(self):
        with inst._state_lock:
            inst._connected = True
            inst._last_connect_params = {"instance_id": "x"}

        with patch.object(inst, "connect_to_server") as mock_connect:
            inst._try_reconnect()

        mock_connect.assert_not_called()

    def test_skip_if_no_params(self):
        with patch.object(inst, "connect_to_server") as mock_connect:
            inst._try_reconnect()

        mock_connect.assert_not_called()


class ConcurrentStateAccessTests(unittest.TestCase):

    def setUp(self):
        _reset_state()

    def tearDown(self):
        _reset_state()

    def test_concurrent_reads_and_writes(self):
        errors = []

        def reader():
            try:
                for _ in range(100):
                    inst.is_connected()
                    inst.get_instance_id()
            except Exception as e:
                errors.append(e)

        def writer():
            try:
                for _ in range(100):
                    inst._close_connection()
                    inst.set_auto_reconnect(True)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [])


class ParseSseLineTests(unittest.TestCase):

    def test_empty_line(self):
        self.assertEqual(inst._parse_sse_line(""), (None, None))

    def test_comment_line(self):
        self.assertEqual(inst._parse_sse_line(":comment"), (None, None))

    def test_event_line(self):
        self.assertEqual(inst._parse_sse_line("event: request"), ("event", "request"))

    def test_data_line(self):
        self.assertEqual(inst._parse_sse_line('data: {"key":1}'), ("data", '{"key":1}'))

    def test_no_colon(self):
        self.assertEqual(inst._parse_sse_line("retry"), ("retry", ""))


if __name__ == "__main__":
    unittest.main()
