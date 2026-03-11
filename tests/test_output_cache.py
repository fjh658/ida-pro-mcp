"""Tests for rpc.py output cache (LRU behavior + thread safety)."""

import pathlib
import sys
import threading
import unittest

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

# Must install stubs before any ida_mcp import
from _ida_stubs import install as _install_stubs
_install_stubs()

from ida_pro_mcp.ida_mcp.rpc import (
    _output_cache,
    _cache_output,
    get_cached_output,
    _truncate_value,
)
import ida_pro_mcp.ida_mcp.rpc as rpc_module


class OutputCacheLRUTests(unittest.TestCase):
    """Test _output_cache LRU eviction and thread safety."""

    def setUp(self):
        self._orig_max = rpc_module.OUTPUT_CACHE_MAX_SIZE
        _output_cache.clear()

    def tearDown(self):
        _output_cache.clear()
        rpc_module.OUTPUT_CACHE_MAX_SIZE = self._orig_max

    def test_basic_cache_and_retrieve(self):
        _cache_output("id1", {"data": 1})
        result = get_cached_output("id1")
        self.assertEqual(result, {"data": 1})

    def test_cache_miss_returns_none(self):
        result = get_cached_output("nonexistent")
        self.assertIsNone(result)

    def test_lru_eviction_removes_least_recently_used(self):
        rpc_module.OUTPUT_CACHE_MAX_SIZE = 3
        _cache_output("a", 1)
        _cache_output("b", 2)
        _cache_output("c", 3)

        # Access "a" to make it recently used
        get_cached_output("a")

        # Insert "d" — should evict "b" (least recently used), not "a"
        _cache_output("d", 4)

        self.assertIsNotNone(get_cached_output("a"))
        self.assertIsNone(get_cached_output("b"))
        self.assertIsNotNone(get_cached_output("c"))
        self.assertIsNotNone(get_cached_output("d"))

    def test_fifo_eviction_when_no_access(self):
        rpc_module.OUTPUT_CACHE_MAX_SIZE = 2
        _cache_output("x", 10)
        _cache_output("y", 20)

        # Insert "z" — should evict "x" (oldest, never accessed)
        _cache_output("z", 30)

        self.assertIsNone(get_cached_output("x"))
        self.assertIsNotNone(get_cached_output("y"))
        self.assertIsNotNone(get_cached_output("z"))

    def test_update_existing_key_moves_to_end(self):
        rpc_module.OUTPUT_CACHE_MAX_SIZE = 2
        _cache_output("a", 1)
        _cache_output("b", 2)

        # Re-cache "a" with new value — should move to end
        _cache_output("a", 100)

        # Insert "c" — should evict "b", not "a"
        _cache_output("c", 3)

        self.assertIsNone(get_cached_output("b"))
        self.assertEqual(get_cached_output("a"), 100)
        self.assertIsNotNone(get_cached_output("c"))

    def test_concurrent_cache_access(self):
        """Multiple threads caching and reading should not crash."""
        rpc_module.OUTPUT_CACHE_MAX_SIZE = 10
        errors = []

        def writer(start):
            try:
                for i in range(50):
                    _cache_output(f"w{start}-{i}", i)
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for i in range(50):
                    get_cached_output(f"w0-{i}")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer, args=(0,)),
            threading.Thread(target=writer, args=(1,)),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [])
        self.assertLessEqual(len(_output_cache), 10)


class TruncateValueTests(unittest.TestCase):
    """Test _truncate_value preview truncation."""

    def test_short_string_unchanged(self):
        self.assertEqual(_truncate_value("hello"), "hello")

    def test_long_string_truncated(self):
        long_str = "a" * 2000
        result = _truncate_value(long_str)
        self.assertIn("2000 chars total", result)
        self.assertTrue(len(result) < len(long_str))

    def test_long_list_truncated(self):
        items = list(range(50))
        result = _truncate_value(items)
        self.assertEqual(len(result), 11)  # 10 items + truncation marker
        self.assertIn("_truncated", result[-1])

    def test_short_list_unchanged(self):
        items = [1, 2, 3]
        result = _truncate_value(items)
        self.assertEqual(result, [1, 2, 3])

    def test_nested_dict_truncated(self):
        data = {"key": "v" * 2000}
        result = _truncate_value(data)
        self.assertIn("2000 chars total", result["key"])


if __name__ == "__main__":
    unittest.main()
