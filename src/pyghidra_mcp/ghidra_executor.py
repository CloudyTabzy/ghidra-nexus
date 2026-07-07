import asyncio
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

_GHIDRA_EXECUTOR: "GhidraExecutor | None" = None


def get_executor() -> "GhidraExecutor":
    if _GHIDRA_EXECUTOR is None:
        raise RuntimeError("GhidraExecutor has not been started")
    return _GHIDRA_EXECUTOR


def set_executor(executor: "GhidraExecutor") -> None:
    global _GHIDRA_EXECUTOR
    _GHIDRA_EXECUTOR = executor


class GhidraExecutor:
    """Single-thread executor for ALL JVM/Ghidra operations.

    Funnels every Ghidra call through one background thread to:

    - Prevent DecompInterface synchronized-method deadlocks
    - Prevent "yanking" of decompiler process mid-operation
    - Guarantee no concurrent write races on Ghidra Program state
    - Keep the MCP asyncio event loop responsive

    Architecture: MCP handlers submit (fn, program_info) tuples via a queue.
    The worker thread pops them, calls fn() directly wrapped in the
    program's rw_lock, and sends the result back through a per-request
    asyncio.Queue. No run_coroutine_threadsafe — the worker IS the
    only thread touching the JVM.
    """

    def __init__(
        self,
        *,
        max_queue_size: int = 100,
        task_timeout: float = 60.0,
    ):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._queue: asyncio.Queue | None = None
        self._max_queue_size = max_queue_size
        self._task_timeout = task_timeout
        self._running = threading.Event()
        self._ready = threading.Event()
        self._current_task_id: str | None = None
        self._current_task_start: float | None = None
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._running.set()

        def _run():
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._worker_loop())

        self._thread = threading.Thread(target=_run, name="ghidra-executor", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10.0)

    async def _worker_loop(self) -> None:
        self._queue = asyncio.Queue(maxsize=self._max_queue_size)
        self._ready.set()
        try:
            while self._running.is_set():
                try:
                    task_id, program_info, fn, result_queue = await asyncio.wait_for(
                        self._queue.get(), timeout=0.5
                    )
                    with self._lock:
                        self._current_task_id = task_id
                        self._current_task_start = time.monotonic()
                    try:
                        rw_lock = getattr(program_info, "rw_lock", None)
                        if rw_lock is not None:
                            with rw_lock:
                                result = fn()
                        else:
                            result = fn()
                        self._tasks_completed += 1
                    except Exception as e:
                        result = e
                        self._tasks_failed += 1
                    finally:
                        with self._lock:
                            self._current_task_id = None
                            self._current_task_start = None
                    try:
                        await asyncio.wait_for(result_queue.put(result), timeout=5.0)
                    except asyncio.TimeoutError:
                        logger.error(
                            "GhidraExecutor worker: result queue put timed out for task '%s'",
                            task_id,
                        )
                except asyncio.TimeoutError:
                    pass
                except asyncio.CancelledError:
                    break
        finally:
            pass

    async def submit(
        self,
        program_info: Any,
        fn: Callable[..., Any],
        *,
        write: bool = False,
        task_id: str = "",
    ) -> Any:
        """Submit a Ghidra operation to the executor thread.

        Args:
            program_info: The ProgramInfo to operate on (dead-flag + RLock).
            fn: The callable to execute synchronously on the executor thread.
            write: Whether this is a write operation (informational).
            task_id: Human-readable identifier for monitoring.
        """
        if getattr(program_info, "dead", False):
            raise RuntimeError(
                f"Program '{getattr(program_info, 'name', 'unknown')}' has been disposed."
            )

        result_queue: asyncio.Queue = asyncio.Queue(maxsize=1)
        await self._queue.put((task_id or "unknown", program_info, fn, result_queue))
        try:
            result = await asyncio.wait_for(result_queue.get(), timeout=self._task_timeout)
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Task '{task_id}' timed out after {self._task_timeout}s. "
                f"Reduce concurrent load or increase timeout."
            )
        if isinstance(result, Exception):
            raise result
        return result

    async def submit_nowait(
        self,
        program_info: Any,
        fn: Callable[..., Any],
        *,
        task_id: str = "",
    ) -> None:
        """Fire-and-forget version. Does not return a result."""
        if getattr(program_info, "dead", False):
            return

        result_queue: asyncio.Queue = asyncio.Queue(maxsize=1)

        def _fire_and_forget():
            try:
                rw_lock = getattr(program_info, "rw_lock", None)
                if rw_lock is not None:
                    with rw_lock:
                        fn()
                else:
                    fn()
            except Exception:
                logger.debug("submit_nowait task '%s' raised", task_id, exc_info=True)

        try:
            await self._queue.put((task_id or "unknown", program_info, _fire_and_forget, result_queue))
        except asyncio.QueueFull:
            pass

    def shutdown(self, timeout: float = 10.0) -> None:
        self._running.clear()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._thread is not None and self._thread.is_alive():
            if self._loop is not None:
                try:
                    self._loop.call_soon_threadsafe(self._loop.stop)
                except Exception:
                    pass
            self._thread.join(timeout=2.0)

    @property
    def stats(self) -> dict:
        with self._lock:
            current_id = self._current_task_id
            current_start = self._current_task_start
            completed = self._tasks_completed
            failed = self._tasks_failed
        queue_depth = self._queue.qsize() if self._queue else 0
        elapsed = 0.0
        if current_start is not None:
            elapsed = time.monotonic() - current_start
        return {
            "tasks_completed": completed,
            "tasks_failed": failed,
            "current_task": current_id,
            "current_task_elapsed": round(elapsed, 1),
            "queue_depth": queue_depth,
        }
