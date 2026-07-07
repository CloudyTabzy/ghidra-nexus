"""Tiny stdio-to-HTTP proxy for OpenCode MCP connection.

This process starts instantly (no JVM, no Ghidra imports). It bridges
OpenCode's stdio MCP connection to a persistent Ghidra HTTP daemon.

If the daemon is not running, the proxy auto-launches it and waits
for it to become ready. Tool calls received before the daemon is ready
return a polite "Ghidra is starting" message.
"""

import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

DAEMON_HOST = os.environ.get("PYGHIDRA_MCP_HOST", "127.0.0.1")
DAEMON_PORT = int(os.environ.get("PYGHIDRA_MCP_PORT", "8000"))
DAEMON_STARTUP_TIMEOUT = float(os.environ.get("PYGHIDRA_MCP_STARTUP_TIMEOUT", "90.0"))
GHIDRA_INSTALL_DIR = os.environ.get("GHIDRA_INSTALL_DIR", "")
PROXY_PID_FILE = os.environ.get("PYGHIDRA_MCP_PID_FILE", "")

_DAEMON_PROCESS: subprocess.Popen | None = None
_DAEMON_READY = threading.Event()
_DAEMON_LOCK = threading.Lock()


def _daemon_url(method: str = "") -> str:
    return f"http://{DAEMON_HOST}:{DAEMON_PORT}/mcp"


def _is_daemon_running() -> bool:
    try:
        s = socket.create_connection((DAEMON_HOST, DAEMON_PORT), timeout=1.0)
        s.close()
        return True
    except (OSError, ConnectionRefusedError):
        return False


def _start_daemon() -> subprocess.Popen | None:
    project_dir = Path(__file__).resolve().parent.parent
    cwd = os.environ.get("PYGHIDRA_MCP_CWD", str(project_dir))

    env = os.environ.copy()
    if GHIDRA_INSTALL_DIR:
        env["GHIDRA_INSTALL_DIR"] = GHIDRA_INSTALL_DIR

    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "pyghidra_mcp",
                "--transport", "streamable-http",
                "--host", DAEMON_HOST,
                "--port", str(DAEMON_PORT),
            ],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return proc
    except Exception:
        return None


def _ensure_daemon() -> bool:
    global _DAEMON_PROCESS

    if _is_daemon_running():
        _DAEMON_READY.set()
        return True

    with _DAEMON_LOCK:
        if _DAEMON_READY.is_set():
            return True

        sys.stderr.write("pyghidra-mcp proxy: starting Ghidra daemon...\n")
        sys.stderr.flush()

        proc = _start_daemon()
        if proc is None:
            sys.stderr.write("pyghidra-mcp proxy: failed to start daemon\n")
            sys.stderr.flush()
            return False

        _DAEMON_PROCESS = proc

        deadline = time.time() + DAEMON_STARTUP_TIMEOUT
        while time.time() < deadline:
            if _is_daemon_running():
                _DAEMON_READY.set()
                sys.stderr.write("pyghidra-mcp proxy: daemon ready\n")
                sys.stderr.flush()
                return True
            if proc.poll() is not None:
                sys.stderr.write(
                    f"pyghidra-mcp proxy: daemon exited with code {proc.returncode}\n"
                )
                sys.stderr.flush()
                return False
            time.sleep(1.0)

        sys.stderr.write(
            f"pyghidra-mcp proxy: daemon timed out after {DAEMON_STARTUP_TIMEOUT}s\n"
        )
        sys.stderr.flush()
        return False


def _forward(request: dict) -> dict | None:
    body = json.dumps(request).encode("utf-8")
    conn = http.client.HTTPConnection(DAEMON_HOST, DAEMON_PORT, timeout=300.0)
    conn.request(
        "POST",
        "/mcp",
        body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    conn.close()

    if resp.status in (200, 202):
        if resp.status == 202:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    if resp.status == 503:
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {
                "code": -32000,
                "message": "Ghidra is still starting (15-30 seconds). Wait and retry.",
            },
        }
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "error": {
            "code": -32000,
            "message": f"Ghidra daemon returned HTTP {resp.status}",
        },
    }


def _cleanup():
    global _DAEMON_PROCESS
    proc = _DAEMON_PROCESS
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    sys.stderr.write(f"pyghidra-mcp proxy: started on port {DAEMON_PORT}, pid={os.getpid()}\n")
    sys.stderr.flush()

    signal.signal(signal.SIGINT, lambda *_: _cleanup() or sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: _cleanup() or sys.exit(0))

    while True:
        try:
            line = stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                sys.stderr.write(f"proxy: bad JSON: {line[:120]}\n")
                sys.stderr.flush()
                continue

            method = request.get("method", "")
            req_id = request.get("id")
            sys.stderr.write(f"proxy: <- {method} (id={req_id})\n")
            sys.stderr.flush()

            if method == "ping":
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}
                stdout.write(json.dumps(resp).encode("utf-8") + b"\n")
                stdout.flush()
                sys.stderr.write(f"proxy: -> ping ok\n")
                sys.stderr.flush()
                continue

            if not _DAEMON_READY.is_set() and method not in ("initialize",):
                stdout.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": -32000,
                                "message": (
                                    "Ghidra daemon is starting up (usually 15-30 seconds). "
                                    "Wait and retry."
                                ),
                            },
                        }
                    ).encode("utf-8")
                    + b"\n"
                )
                stdout.flush()
                continue

            if method == "initialize":
                threading.Thread(target=_ensure_daemon, daemon=True).start()
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "pyghidra-mcp-proxy",
                            "version": "0.2.3",
                        },
                    },
                }
                stdout.write(json.dumps(response).encode("utf-8") + b"\n")
                stdout.flush()
                sys.stderr.write("proxy: -> initialize ok (daemon launching in bg)\n")
                sys.stderr.flush()
                continue

            if method == "notifications/initialized":
                continue

            response = _forward(request)
            if response is not None:
                stdout.write(json.dumps(response, default=str).encode("utf-8") + b"\n")
                stdout.flush()
                sys.stderr.write(f"proxy: -> forwarded {method} (id={req_id})\n")
                sys.stderr.flush()

        except (BrokenPipeError, KeyboardInterrupt):
            break
        except Exception:
            continue

    _cleanup()


if __name__ == "__main__":
    main()
