"""Lazy Ghidra context that defers JVM startup to a background thread.

The MCP server starts instantly over stdio. Tools return a polite
"Ghidra is still starting" message until the JVM is fully initialized.
Once ready, the LazyPyGhidraContext wraps a real PyGhidraContext and
delegates all calls to it transparently.
"""

import logging
import threading
from typing import TYPE_CHECKING, Any

from pyghidra_mcp.context_protocol import MCPContext
from pyghidra_mcp.models import ImportRequestResult, ProgramInfo as ProgramInfoModel

if TYPE_CHECKING:
    from pyghidra_mcp.context import ProgramInfo, PyGhidraContext

logger = logging.getLogger(__name__)


class LazyPyGhidraContext(MCPContext):
    """MCPContext that defers real Ghidra context initialization.

    Wraps a background JVM startup thread. Until the JVM is ready,
    all tool-required methods raise RuntimeError with a user-friendly
    retry message. After initialization, delegates to the real context.
    """

    def __init__(
        self,
        context_init_fn,
        *,
        get_programs_fn=None,
    ):
        self._real: PyGhidraContext | None = None
        self._init_fn = context_init_fn
        self._get_programs_fn = get_programs_fn
        self._ready = threading.Event()
        self._init_error: BaseException | None = None
        self._lock = threading.Lock()
        self._bg_thread: threading.Thread | None = None

    def _ensure_ready(self):
        if self._real is not None:
            return self._real
        if not self._ready.is_set():
            raise RuntimeError(
                "Ghidra JVM is still starting up (usually 15-30 seconds). "
                "Wait and retry your tool call."
            )
        if self._init_error is not None:
            raise RuntimeError(
                f"Ghidra initialization failed: {self._init_error}. "
                f"Check the server logs for details."
            )
        with self._lock:
            if self._real is not None:
                return self._real
            self._real = self._init_fn()
        return self._real

    def start_background_init(self) -> None:
        if self._bg_thread is not None:
            return

        def _init():
            try:
                self._init_fn()
                self._ready.set()
                logger.info("Ghidra JVM initialized successfully.")
            except BaseException as e:
                self._init_error = e
                self._ready.set()
                logger.critical("Ghidra JVM initialization failed: %s", e, exc_info=True)

        self._bg_thread = threading.Thread(
            target=_init, name="ghidra-init", daemon=True
        )
        self._bg_thread.start()

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and self._init_error is None

    @property
    def programs(self) -> dict[str, Any]:
        real = self._real
        if real is not None:
            return real.programs
        if self._get_programs_fn is not None:
            return self._get_programs_fn()
        return {}

    # --- MCPContext protocol methods ---

    def get_program_info(self, binary_name: str) -> "ProgramInfo":
        return self._ensure_ready().get_program_info(binary_name)

    def list_binaries(self) -> list[str]:
        return self._ensure_ready().list_binaries()

    def list_binary_domain_files(self) -> list[Any]:
        return self._ensure_ready().list_binary_domain_files()

    def list_program_infos(self) -> list["ProgramInfo"]:
        real = self._real
        if real is not None:
            return real.list_program_infos()
        return []

    def list_project_binary_infos(self) -> list[ProgramInfoModel]:
        real = self._real
        if real is not None:
            return real.list_project_binary_infos()
        return []

    def delete_program(self, program_name: str) -> bool:
        return self._ensure_ready().delete_program(program_name)

    def import_binary_backgrounded(
        self, binary_path: str | Any
    ) -> ImportRequestResult:
        return self._ensure_ready().import_binary_backgrounded(binary_path)

    def save(self) -> None:
        real = self._real
        if real is not None:
            real.save()

    def close(self, save: bool = True) -> None:
        real = self._real
        if real is not None:
            real.close()
