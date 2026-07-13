import queue
import threading
from collections.abc import Callable
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompInterface


class DecompilerPool:
    """Thread-safe pool of DecompInterface instances.

    Size is configurable (default 4) to support concurrent agent decompilations
    on the same binary. Includes a disposal flag and acquire timeout to prevent
    deadlocks during shutdown.

    The critical fix: blocking queue.get() is ALWAYS called outside the
    _created_lock, preventing the classic lock+blocking-get deadlock between
    _ensure_available and dispose().
    """

    def __init__(
        self,
        factory: Callable[[], "DecompInterface"],
        *,
        size: int = 4,
        acquire_timeout: float = 30.0,
    ) -> None:
        self._factory = factory
        self._size = max(1, size)
        self._queue: queue.LifoQueue[DecompInterface] = queue.LifoQueue(maxsize=self._size)
        self._created: list[DecompInterface] = []
        self._created_lock = threading.Lock()
        self._acquire_timeout = acquire_timeout
        self._disposing = threading.Event()

    def _create(self) -> "DecompInterface":
        decompiler = self._factory()
        with self._created_lock:
            self._created.append(decompiler)
        return decompiler

    def _pool_is_full(self) -> bool:
        with self._created_lock:
            return len(self._created) >= self._size

    def _ensure_available(self) -> "DecompInterface":
        if self._disposing.is_set():
            raise RuntimeError("DecompilerPool is shutting down; cannot acquire a decompiler")
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            if not self._pool_is_full():
                return self._create()
            try:
                return self._queue.get(timeout=self._acquire_timeout)
            except queue.Empty:
                raise RuntimeError(
                    f"DecompilerPool exhausted: all {self._size} decompilers busy "
                    f"after {self._acquire_timeout}s. Reduce concurrent decompile requests "
                    f"or increase pool size."
                )

    @contextmanager
    def acquire(self):
        decompiler = self._ensure_available()
        try:
            yield decompiler
        finally:
            if not self._disposing.is_set():
                try:
                    self._queue.put_nowait(decompiler)
                except queue.Full:
                    pass

    def invalidate_all(self) -> None:
        with self._created_lock:
            decompilers = list(self._created)
        for decompiler in decompilers:
            for method_name in ("flushCache", "resetDecompiler"):
                method = getattr(decompiler, method_name, None)
                if method is not None:
                    method()
                    break

    def dispose(self) -> None:
        self._disposing.set()
        with self._created_lock:
            decompilers = list(self._created)
            self._created.clear()
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
        for decompiler in decompilers:
            for method_name in ("dispose", "closeProgram"):
                method = getattr(decompiler, method_name, None)
                if method is not None:
                    method()
                    break
