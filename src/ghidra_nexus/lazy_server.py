"""Lazy Ghidra MCP server — starts as a lightweight HTTP daemon without JVM.

Registers a single 'wake_ghidra' tool. When the agent calls it, the JVM
starts, the Ghidra project initializes, all analysis tools register
dynamically, and wake_ghidra removes itself.

Usage:
    uv run ghidra-nexus --transport streamable-http
"""

import functools
import logging
import sys
import threading
import time

import click
import pyghidra

from ghidra_nexus import __version__, mcp_tools
from ghidra_nexus.context import PyGhidraContext
from ghidra_nexus.context_protocol import MCPContext
from ghidra_nexus.ghidra_executor import GhidraExecutor, set_executor
from ghidra_nexus.project_spec import DEFAULT_PROJECT_NAME, ProjectSpec
from ghidra_nexus.watchdog import Watchdog, set_watchdog

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class LazyGhidraApp:
    """Manages deferred JVM startup and dynamic tool registration."""

    def __init__(self, mcp, project_dir, project_name, lazy=True):
        self.mcp = mcp
        self.project_dir = project_dir
        self.project_name = project_name
        self.context: MCPContext | None = None
        self.executor: GhidraExecutor | None = None
        self.watchdog = None
        self._awake = False
        self._lock = threading.Lock()

        if lazy:
            self._register_wake_only()
        else:
            self._full_init()

    def _full_init(self):
        """Eager startup — JVM + tools immediately."""
        pyghidra.start(False)
        self.context = PyGhidraContext(
            project_name=self.project_name,
            project_path=self.project_dir,
            threaded=True,
            wait_for_analysis=False,
        )
        c = self.context
        if len(c.list_binaries()) == 0:
            logger.warning("No binaries in project. Use import_binary to add one.")
        self._start_infrastructure(c)
        self._awake = True

    def _start_infrastructure(self, context):
        self.executor = GhidraExecutor(max_queue_size=100, task_timeout=60.0)
        self.executor.start()
        set_executor(self.executor)
        self.watchdog = Watchdog(executor=self.executor, get_programs=lambda: context.programs)
        self.watchdog.start()
        set_watchdog(self.watchdog)

    def _register_wake_only(self):
        """Register only the wake_ghidra tool. All others come after activation."""

        async def wake_ghidra(ctx=None) -> str:
            return self._activate()

        self.mcp.add_tool(wake_ghidra, name="wake_ghidra", description="Start the Ghidra analysis engine. Call this before any other tool.")

        async def ping_status(ctx=None) -> str:
            return "Ghidra is asleep. Call wake_ghidra to start the engine." if not self._awake else "Ghidra is awake and ready."

        self.mcp.add_tool(ping_status, name="ghidra_status", description="Check whether Ghidra is awake or asleep.")

    def _activate(self):
        """Start the JVM and register all analysis tools dynamically."""
        with self._lock:
            if self._awake:
                return "Ghidra is already awake."
            self._awake = True

        logger.info("Agent triggered wake-up. Starting Ghidra JVM...")
        t0 = time.time()

        self._full_init()

        self._register_all_tools()

        elapsed = time.time() - t0
        msg = f"Ghidra engine started in {elapsed:.0f}s. All tools available."
        logger.info(msg)
        return msg

    def _register_all_tools(self):
        """Register every MCP analysis tool on the running FastMCP server."""
        tools = [
            (mcp_tools.decompile_function, "decompile_function"),
            (mcp_tools.search_symbols_by_name, "search_symbols_by_name"),
            (mcp_tools.search_code, "search_code"),
            (mcp_tools.list_project_binaries, "list_project_binaries"),
            (mcp_tools.list_project_binary_metadata, "list_project_binary_metadata"),
            (mcp_tools.rename_function, "rename_function"),
            (mcp_tools.rename_variable, "rename_variable"),
            (mcp_tools.set_variable_type, "set_variable_type"),
            (mcp_tools.set_function_prototype, "set_function_prototype"),
            (mcp_tools.set_comment, "set_comment"),
            (mcp_tools.delete_project_binary, "delete_project_binary"),
            (mcp_tools.list_exports, "list_exports"),
            (mcp_tools.list_imports, "list_imports"),
            (mcp_tools.list_xrefs, "list_xrefs"),
            (mcp_tools.search_strings, "search_strings"),
            (mcp_tools.read_bytes, "read_bytes"),
            (mcp_tools.disassemble, "disassemble"),
            (mcp_tools.gen_callgraph, "gen_callgraph"),
            (mcp_tools.analysis_status, "analysis_status"),
            (mcp_tools.import_binary, "import_binary"),
            (mcp_tools.save, "save"),
        ]
        for fn, name in tools:
            try:
                self.mcp.add_tool(fn, name=name)
            except Exception:
                logger.warning("Failed to register tool %s — may already exist", name, exc_info=True)

        try:
            self.mcp.remove_tool("wake_ghidra")
        except Exception:
            pass

    def close(self):
        if self.watchdog:
            self.watchdog.stop()
        if self.executor:
            self.executor.shutdown(timeout=5.0)
        if self.context:
            self.context.close()
