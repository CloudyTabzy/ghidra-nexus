"""Proxy Ghidra executor that forwards tool calls to the daemon via HTTP.

This replaces GhidraExecutor in the proxy process. No JVM needed -
just HTTP forwarding to the persistent Ghidra daemon.
"""

import asyncio
import json
import logging
import socket
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_DAEMON_HOST = "127.0.0.1"

_DAEMON_PORT = 8000
_DAEMON_STARTUP_TIMEOUT = 90.0
_DAEMON_PROC: subprocess.Popen | None = None
_DAEMON_READY = False
_DAEMON_LOCK = asyncio.Lock()


async def _is_daemon_running() -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(_DAEMON_HOST, _DAEMON_PORT), timeout=1.0
        )
        writer.close()
        return True
    except Exception:
        return False


async def _start_daemon() -> subprocess.Popen | None:
    global _DAEMON_PROC

    project_dir = Path(__file__).resolve().parent.parent
    ghdir = sys._xoptions.get("GHIDRA_INSTALL_DIR", "")

    env = {}
    if ghdir:
        env["GHIDRA_INSTALL_DIR"] = ghdir

    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ghidra_nexus",
                "--transport", "streamable-http",
                "--host", _DAEMON_HOST,
                "--port", str(_DAEMON_PORT),
            ],
            cwd=project_dir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _DAEMON_PROC = proc
        return proc
    except Exception:
        return None


async def _ensure_daemon() -> bool:
    global _DAEMON_READY

    if _DAEMON_READY:
        return True
    if await _is_daemon_running():
        _DAEMON_READY = True
        return True

    async with _DAEMON_LOCK:
        if _DAEMON_READY:
            return True

        proc = await _start_daemon()
        if proc is None:
            return False

        deadline = time.time() + _DAEMON_STARTUP_TIMEOUT
        while time.time() < deadline:
            if await _is_daemon_running():
                _DAEMON_READY = True
                return True
            if proc.poll() is not None:
                return False
            await asyncio.sleep(1.0)

        return False


async def _forward_raw(request: dict) -> dict | None:
    body = json.dumps(request).encode("utf-8")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(_DAEMON_HOST, _DAEMON_PORT), timeout=5.0
        )
        http_req = (
            f"POST /mcp HTTP/1.1\r\n"
            f"Host: {_DAEMON_HOST}:{_DAEMON_PORT}\r\n"
            f"Content-Type: application/json\r\n"
            f"Accept: application/json, text/event-stream\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8") + body

        writer.write(http_req)
        await writer.drain()

        response_data = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=300.0)
            if not chunk:
                break
            response_data += chunk

        writer.close()

        text = response_data.decode("utf-8", errors="replace")
        parts = text.split("\r\n\r\n", 1)
        if len(parts) < 2:
            return None
        body_text = parts[1]

        if body_text.strip():
            return json.loads(body_text)
        return None
    except Exception:
        return None


class ProxyGhidraExecutor:
    """Replacement for GhidraExecutor in the proxy process.

    Forwards all tool operations to the persistent Ghidra daemon
    over HTTP. The proxy process has zero JVM/Ghidra dependencies.
    """

    def __init__(self):
        self._tasks_completed = 0
        self._tasks_failed = 0

    async def submit(self, program_info, fn, *, write=False, task_id=""):
        """Forward directly - fn is not used.

        We intercept at the mcp_tools handler level and call the
        forward_raw method with the full MCP tool call request.
        """
        raise NotImplementedError("Use forward_tool_call instead")

    async def forward_tool_call(self, tool_name: str, arguments: dict) -> dict:
        if not _DAEMON_READY:
            if not await _ensure_daemon():
                raise RuntimeError(
                    "Ghidra daemon failed to start. Check that GHIDRA_INSTALL_DIR "
                    "is set and the Ghidra installation is valid."
                )
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        response = await _forward_raw(request)
        if response is None:
            self._tasks_failed += 1
            raise RuntimeError(f"Daemon returned empty response for {tool_name}")
        self._tasks_completed += 1
        if "error" in response:
            msg = response["error"].get("message", "Unknown error")
            raise RuntimeError(f"Tool {tool_name} failed: {msg}")
        return response.get("result", {})

    @property
    def idle(self) -> bool:
        return True

    @property
    def stats(self) -> dict:
        return {
            "tasks_completed": self._tasks_completed,
            "tasks_failed": self._tasks_failed,
            "active_calls": 0,
            "busy_since": 0.0,
            "queue_depth": 0,
        }
