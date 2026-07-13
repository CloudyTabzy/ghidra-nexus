"""Manual end-to-end smoke test for survey_binary.

Spins up the MCP server in **stdio** mode (RE-MCP pattern) against a real
Ghidra install, imports a real Windows system binary (find.exe — no gcc
needed), waits for analysis, calls survey_binary, and pretty-prints
the result.

We use stdio instead of streamable-http because the latter's
GET-stream has a tendency to drop responses during multi-minute
auto-analysis (an upstream MCP-client issue). stdio is the same
transport the OpenCode MCP client uses.

Run from ``pyghidra-mcp/``:

.. code-block:: powershell

    $env:GHIDRA_INSTALL_DIR = 'C:\\Dev\\Ghidra-MCP\\ghidra_12.1.2_PUBLIC'
    uv run python tests/manual/manual_survey_e2e.py

This file is *not* a pytest test (no ``test_`` prefix) and is not collected
by the regular suite — it requires ``GHIDRA_INSTALL_DIR`` to be set and
takes ~5-10 minutes for a cold find.exe analysis (PDB download + Ghidra
auto-analysis).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# PyGhidraContext only needs its static ``_gen_unique_bin_name`` to translate
# the queued path into the project's unique program name. Importing the
# module does NOT start the Ghidra JVM (that's done inside the server
# subprocess), so it's safe to import here in the test client.
from pyghidra_mcp.context import PyGhidraContext

REPO_ROOT = Path(__file__).resolve().parents[2]
GHIDRA_INSTALL = Path(r"C:\Dev\Ghidra-MCP\ghidra_12.1.2_PUBLIC")
TEST_BINARY = Path(r"C:\Windows\System32\find.exe")


def _require_ghidra_install() -> None:
    if not GHIDRA_INSTALL.is_dir():
        print(
            f"ERROR: Ghidra install not found at {GHIDRA_INSTALL}.\n"
            "Set GHIDRA_INSTALL_DIR or update GHIDRA_INSTALL in this script.",
            file=sys.stderr,
        )
        sys.exit(2)


def _require_test_binary() -> None:
    if not TEST_BINARY.is_file():
        print(
            f"ERROR: Test binary not found at {TEST_BINARY}.",
            file=sys.stderr,
        )
        sys.exit(2)


def _wait_for_port(host: str, port: int, timeout_s: float = 60.0) -> None:
    """Poll TCP connect until the server's port accepts connections."""
    deadline = time.time() + timeout_s
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError as exc:
            last_err = exc
            time.sleep(0.5)
    raise TimeoutError(
        f"Server did not start listening on {host}:{port} within {timeout_s}s "
        f"(last error: {last_err})"
    )


async def _call_tool(
    session,
    name: str,
    arguments: dict[str, Any],
    *,
    timeout_s: float = 120.0,
) -> dict:
    """Call a tool and return the parsed JSON payload."""
    import asyncio as _asyncio

    response = await _asyncio.wait_for(
        session.call_tool(name, arguments), timeout=timeout_s
    )
    if not response.content:
        raise RuntimeError(f"{name}: empty response")
    text = response.content[0].text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Some tools return non-JSON; treat as text
        return {"raw_text": text}


def _start_server(project_path: Path):
    """Build the StdioServerParameters that stdio_client will spawn.

    Stdio uses the RE-MCP pattern (JVM on main thread, FastMCP stdio on
    daemon thread) so the JVM and the FastMCP event loop coexist safely.
    """
    from mcp import StdioServerParameters

    env = os.environ.copy()
    env["GHIDRA_INSTALL_DIR"] = str(GHIDRA_INSTALL)
    env.pop("PYTHONPATH", None)

    project_path.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "pyghidra_mcp",
        "--transport",
        "stdio",
        "--project-path",
        str(project_path),
        "--project-name",
        "survey_e2e",
        "--wait-for-analysis",
    ]
    print(f"Starting server (stdio): {' '.join(cmd)}")
    # ``StdioServerParameters.command`` must be a single string; the args
    # follow as the rest of the argv vector.
    return StdioServerParameters(command=cmd[0], args=cmd[1:], env=env, cwd=str(REPO_ROOT))


def _drain_server_output(proc: subprocess.Popen) -> None:
    """Best-effort: print the server's last lines if it died."""
    try:
        if proc.poll() is not None and proc.stdout is not None:
            tail = proc.stdout.read()[-2000:]
            print("\n--- server output (last 2KB) ---")
            print(tail)
    except Exception:
        pass


def _print_survey_summary(payload: dict) -> None:
    """Pretty-print a survey_binary payload — top-level only, no full dump."""
    print("\n========== survey_binary result ==========")
    print(f"ok: {payload.get('ok')}")
    meta = payload.get("metadata", {})
    print(
        f"binary: {meta.get('module')}  arch: {meta.get('arch')}  "
        f"image_size: {meta.get('image_size')}"
    )
    print(f"md5:   {meta.get('md5')}")
    print(f"sha256: {meta.get('sha256')}")

    stats = payload.get("statistics", {})
    print(
        f"functions: {stats.get('total_functions')} "
        f"(named={stats.get('named_functions')}, "
        f"library={stats.get('library_functions')}, "
        f"thunk={stats.get('thunk_functions')}, "
        f"unnamed={stats.get('unnamed_functions')})"
    )
    print(
        f"strings: {stats.get('total_strings')}  "
        f"segments: {stats.get('total_segments')}"
    )

    entrypoints = [ep.get("name") or ep.get("addr") for ep in payload.get("entrypoints", [])]
    print(f"entrypoints: {entrypoints}")

    interesting = payload.get("interesting_strings") or []
    if interesting:
        print("\ntop interesting strings (by xref count):")
        for s in interesting[:5]:
            print(f"  {s['xref_count']:>3}x  {s['string']!r}  @ {s['addr']}")

    interesting = payload.get("interesting_functions") or []
    if interesting:
        print("\ntop interesting functions (by xref count):")
        for f in interesting[:5]:
            print(
                f"  {f['xref_count']:>3}x  type={f['type']:<11}  "
                f"size={f['size']:<6}  callees={f['callee_count']:<3}  "
                f"{f['name']!r}"
            )

    cats = payload.get("imports_by_category") or {}
    if cats:
        print("\nimports by category:")
        for cat in ("crypto", "network", "file_io", "process", "registry", "other"):
            n = len(cats.get(cat, []))
            if n:
                sample = cats[cat][:3]
                names = ", ".join(s["name"] for s in sample)
                more = f" +{n - len(sample)} more" if n > len(sample) else ""
                print(f"  {cat:<10}  {n:>3}  ({names}{more})")

    cgs = payload.get("call_graph_summary") or {}
    if cgs:
        print(
            f"\ncall graph: total_edges={cgs.get('total_edges')}  "
            f"max_depth_estimate={cgs.get('max_depth_estimate')}  "
            f"leaves={cgs.get('leaf_functions_count')}  "
            f"roots={len(cgs.get('root_functions', []))}"
        )

    note = payload.get("note")
    if note:
        print(f"\nnote: {note}")

    print("===========================================")


async def _run() -> int:
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    _require_ghidra_install()
    _require_test_binary()

    project_root = Path(tempfile.mkdtemp(prefix="survey_e2e_"))
    server_params = _start_server(project_root)

    try:
        print("Server started; connecting via stdio…")

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("MCP session initialized")

                # 1) Import the test binary
                print(f"\n[1/4] import_binary({TEST_BINARY})")
                imp = await _call_tool(
                    session,
                    "import_binary",
                    {"binary_path": str(TEST_BINARY)},
                    timeout_s=60.0,
                )
                print(f"      {imp}")
                queued_path = imp.get("queued_paths", [None])[0]
                if not queued_path:
                    print("ERROR: import_binary did not queue the binary.", file=sys.stderr)
                    return 1

                # Convert the queued path to the unique program name the
                # server actually stores it under — otherwise our poll loop
                # will never match the entry in `list_project_binaries`.
                # The full key is ``/<basename>-<sha1-6>`` (root folder prefix).
                binary_name = "/" + PyGhidraContext._gen_unique_bin_name(queued_path)
                print(f"      resolved program name: {binary_name!r}")

                # 2) Wait for analysis
                # find.exe pulls a ~30MB PDB from msdl.microsoft.com on first
                # import, then runs full Ghidra auto-analysis. The wall time
                # is ~5-8 minutes; budget 10 minutes for a cold start.
                print(
                    f"\n[2/4] analysis_status() — waiting for analysis_complete=true "
                    f"on {binary_name!r}"
                )
                deadline = time.time() + 600
                poll_attempt = 0
                while time.time() < deadline:
                    poll_attempt += 1
                    try:
                        status = await _call_tool(
                            session,
                            "list_project_binaries",
                            {},
                            timeout_s=60.0,
                        )
                    except (TimeoutError, Exception) as exc:
                        print(
                            f"      poll #{poll_attempt}: list_project_binaries "
                            f"failed ({type(exc).__name__}); retrying in 10s"
                        )
                        await asyncio.sleep(10.0)
                        continue

                    programs = status.get("programs", [])
                    match = next(
                        (p for p in programs if p.get("name") == binary_name),
                        None,
                    )
                    if match and match.get("analysis_complete"):
                        print(
                            f"      ready after {poll_attempt} polls: {match['name']}  "
                            f"code_indexed={match.get('code_indexed')}  "
                            f"strings_indexed={match.get('strings_indexed')}"
                        )
                        break
                    print(
                        f"      poll #{poll_attempt}: {len(programs)} binaries, "
                        f"match={match is not None}, "
                        f"analysis_complete={match.get('analysis_complete') if match else 'N/A'}"
                    )
                    await asyncio.sleep(10.0)
                else:
                    print(
                        f"ERROR: analysis did not complete within 600s. "
                        f"Last seen match: {match}",
                        file=sys.stderr,
                    )
                    return 1

                # 3) survey_binary — standard
                print(f"\n[3/4] survey_binary({binary_name!r}, 'standard')")
                standard = await _call_tool(
                    session,
                    "survey_binary",
                    {"binary_name": binary_name, "detail_level": "standard"},
                    timeout_s=120.0,
                )
                _print_survey_summary(standard)

                # 4) survey_binary — minimal (for comparison)
                print(f"\n[4/4] survey_binary({binary_name!r}, 'minimal')")
                minimal = await _call_tool(
                    session,
                    "survey_binary",
                    {"binary_name": binary_name, "detail_level": "minimal"},
                    timeout_s=60.0,
                )
                print(
                    f"      metadata: {minimal.get('metadata', {}).get('module')!r}  "
                    f"statistics: {minimal.get('statistics')}  "
                    f"entrypoints: {len(minimal.get('entrypoints', []))}  "
                    f"interesting_strings: {minimal.get('interesting_strings')}  "
                    f"(None = correctly omitted)"
                )

        return 0
    finally:
        # stdio_client tears down the subprocess when its context exits,
        # so there's no Popen to terminate here.
        pass


if __name__ == "__main__":
    sys.exit(asyncio.run(_run()))
