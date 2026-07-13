import logging
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghidra_nexus.ghidra_executor import GhidraExecutor

logger = logging.getLogger(__name__)

_WATCHDOG: "Watchdog | None" = None


def get_watchdog() -> "Watchdog | None":
    return _WATCHDOG


def set_watchdog(watchdog: "Watchdog") -> None:
    global _WATCHDOG
    _WATCHDOG = watchdog


class Watchdog:
    """Monitors GhidraExecutor health and program state for the MCP server.

    Detects:
    - Task stalls (a single operation running too long)
    - Queue congestion (too many pending tasks)
    - Error spikes (rapid failures suggesting JVM instability)
    - Dead programs still referenced in the programs dict
    """

    def __init__(
        self,
        executor: "GhidraExecutor",
        get_programs: Any | None = None,
        *,
        interval: float = 5.0,
        task_stall_threshold: float = 60.0,
        error_rate_threshold: int = 5,
        queue_depth_warn: int = 10,
        queue_depth_critical: int = 30,
    ):
        self._executor = executor
        self._get_programs = get_programs
        self._interval = interval
        self._task_stall_threshold = task_stall_threshold
        self._error_rate_threshold = error_rate_threshold
        self._queue_depth_warn = queue_depth_warn
        self._queue_depth_critical = queue_depth_critical
        self._error_timestamps: deque[float] = deque()
        self._running = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._running.set()
        self._thread = threading.Thread(target=self._run, name="pyghidra-watchdog", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while self._running.wait(self._interval):
            self._check_task_stalls()
            self._check_queue_depth()
            self._check_error_rate()
            self._check_program_health()

    def _check_task_stalls(self) -> None:
        stats = self._executor.stats
        busy_for = stats.get("busy_since", 0)
        if busy_for > self._task_stall_threshold:
            logger.warning(
                "Watchdog: executor busy for %.0fs with %s active calls (threshold=%.0fs) -- "
                "possible stall",
                busy_for, stats.get("active_calls", 0), self._task_stall_threshold,
            )

    def _check_queue_depth(self) -> None:
        stats = self._executor.stats
        depth = stats.get("queue_depth", 0)
        if depth > self._queue_depth_critical:
            logger.critical(
                "Watchdog: executor queue depth=%s (critical threshold=%s) -- "
                "SEVERE congestion. Reduce concurrent agent load.",
                depth, self._queue_depth_critical,
            )
        elif depth > self._queue_depth_warn:
            logger.warning(
                "Watchdog: executor queue depth=%s (warning threshold=%s) -- congestion building",
                depth, self._queue_depth_warn,
            )

    def _check_error_rate(self) -> None:
        now = time.time()
        cutoff = now - 60
        while self._error_timestamps and self._error_timestamps[0] < cutoff:
            self._error_timestamps.popleft()
        if len(self._error_timestamps) > self._error_rate_threshold:
            logger.critical(
                "Watchdog: %s errors in the last 60s (threshold=%s) -- "
                "possible JVM instability. Check Ghidra health.",
                len(self._error_timestamps), self._error_rate_threshold,
            )

    def _check_program_health(self) -> None:
        if self._get_programs is None:
            return
        try:
            programs = self._get_programs()
            if not isinstance(programs, dict):
                return
            for path, info in programs.items():
                if getattr(info, "dead", False):
                    logger.warning(
                        "Watchdog: program '%s' is dead but still in programs dict", path
                    )
                pool = getattr(info, "decompiler_pool", None)
                if pool is not None and getattr(pool, "_disposing", threading.Event()).is_set():
                    logger.warning(
                        "Watchdog: decompiler pool for '%s' is in disposing state", path
                    )
        except Exception:
            logger.debug("Watchdog: failed to inspect program health", exc_info=True)

    def record_error(self) -> None:
        self._error_timestamps.append(time.time())

    def stop(self) -> None:
        self._running.clear()
