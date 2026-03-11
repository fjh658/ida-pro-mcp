import logging
import queue
import functools
import os
import sys
import threading
import time
import idaapi
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""

    pass


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 15.0


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


call_stack = queue.LifoQueue()


def _sync_wrapper(ff, dispatch_timeout=None):
    """Call a function ff on IDA main thread with batch mode enabled.

    Batch mode must be set and restored on the IDA main thread; otherwise,
    global IDA state can become inconsistent and affect user interactions
    (for example, the G-key jump dialog).

    execute_sync is run in a daemon thread so the caller can time out
    instead of blocking forever when the main thread is occupied by a
    modal dialog or long-running operation (#217).

    On timeout, a cancelled flag is set so the stale callback becomes a
    no-op when the main thread eventually picks it up — this prevents
    unintended side effects (e.g. a rename/patch executing after the
    caller already reported failure) and frees the daemon thread sooner.
    """

    if dispatch_timeout is None:
        dispatch_timeout = _get_tool_timeout_seconds() + 10.0

    res_container = queue.Queue()
    cancelled = threading.Event()

    def runned():
        # If the caller already timed out, skip execution to avoid
        # stale side effects and free the daemon thread sooner.
        if cancelled.is_set():
            return

        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            res_container.put(IDASyncError(error_str))
            return

        call_stack.put((ff.__name__))
        # Enable batch mode on the IDA main thread to avoid interactive dialogs from MCP tools
        old_batch = idc.batch(1)
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            # Restore batch mode state on the IDA main thread
            idc.batch(old_batch)
            call_stack.get()

    # Run execute_sync in a daemon thread to avoid blocking forever
    # when the main thread is occupied by a modal dialog (#217).
    t = threading.Thread(
        target=lambda: idaapi.execute_sync(runned, idaapi.MFF_WRITE),
        daemon=True,
    )
    t.start()

    try:
        res = res_container.get(timeout=dispatch_timeout)
    except queue.Empty:
        # Mark as cancelled so the stale callback is skipped when the
        # main thread eventually picks it up (#217).
        cancelled.set()
        raise IDAError(
            "Request timed out waiting for IDA main thread. "
            "Please dismiss any open dialogs in IDA."
        )
    if isinstance(res, Exception):
        raise res
    return res


def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(ff, timeout_override: float | None = None):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Note: Batch mode is handled in _sync_wrapper to ensure it is always
    applied consistently for all synchronized operations.
    """
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()

    # dispatch_timeout covers both main-thread dispatch wait + tool execution.
    # The profile-based timeout (below) provides finer-grained control during
    # execution; dispatch_timeout is the outer safety net against hangs (#217).
    dispatch_timeout = timeout + 10.0

    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines)
            deadline = time.monotonic() + timeout if timeout > 0 else None

            def profilefunc(frame, event, arg):
                # Check cancellation first (higher priority)
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, dispatch_timeout=dispatch_timeout)
    return _sync_wrapper(ff, dispatch_timeout=dispatch_timeout)


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func

    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets

    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
