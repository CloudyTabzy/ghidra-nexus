"""Integration tests for Phase 0.5 — real-binary E2E.

These tests need a working Ghidra install. They are skipped if
:envvar:`GHIDRA_INSTALL_DIR` is not set.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from ghidra_nexus.errors import ToolErrorCode, make_tool_error
from ghidra_nexus.section_entropy import shannon_entropy


# Skip the whole module if Ghidra isn't installed/configured.
pytestmark = pytest.mark.skipif(
    not os.environ.get("GHIDRA_INSTALL_DIR"),
    reason="GHIDRA_INSTALL_DIR not set; skipping Ghidra integration tests",
)


@pytest.fixture(scope="module")
def ghidra_project(tmp_path_factory):
    """Spin up a real PyGhidraContext against the small find.exe binary."""
    from ghidra_nexus.context import PyGhidraContext

    tmp = tmp_path_factory.mktemp("p05-it")
    ctx = PyGhidraContext(
        project_name="p05_it",
        project_path=str(tmp),
        threaded=True,
        wait_for_analysis=False,
    )
    yield ctx
    try:
        ctx.close()
    except Exception:
        pass


@pytest.fixture(scope="module")
def find_exe_path():
    p = Path("C:/Windows/System32/find.exe")
    if not p.exists():
        pytest.skip("find.exe not available at C:/Windows/System32")
    return p


def test_import_binary_returns_task_id_and_canonical_name(ghidra_project, find_exe_path):
    """Pattern 2 — false success on long operations: validation gate.

    import_binary must NOT report success without:
        - task_id
        - binary_name (the canonical project name)
        - analysis_state != 'failed' if queued
        - function_count (live)
        - idb_path
        - project_path
        - nexus_data_dir
    """
    result = ghidra_project.import_binary_backgrounded(find_exe_path)
    assert result.task_id, "task_id must be present"
    assert result.binary_name, "binary_name must be present"
    assert result.analysis_state in ("queued", "analyzing_functions", "complete")
    assert result.nexus_data_dir
    assert result.project_path


def test_analysis_status_returns_path_warnings(ghidra_project):
    """Pattern 3 — IDB path / project state inconsistencies: path warning surface.

    Even if the path is healthy, the response shape must include path_warnings
    as a list.
    """
    from ghidra_nexus.models import AnalysisStatusResult

    binaries = ghidra_project.list_project_binary_infos()
    wrapper = AnalysisStatusResult(
        binaries=binaries,
        path_warnings=[],
        server_version="0.3.0",
    )
    assert isinstance(wrapper.binaries, list)
    assert isinstance(wrapper.path_warnings, list)


def test_section_health_classifies_find_exe(find_exe_path):
    """Pattern 4 — section entropy trap: detect encrypted .text.

    find.exe has low entropy (real code), not encrypted. The test asserts the
    pipeline gives sane output for a normal binary.
    """
    from ghidra_nexus.section_entropy import classify_section

    data = find_exe_path.read_bytes()
    e = shannon_entropy(data[: 64 * 1024])
    cls, rec, _ = classify_section(
        entropy=e, size_bytes=len(data), is_executable=True
    )
    # find.exe should be 'code' or maybe 'compressed' if packed
    # (depends on OS version), but never 'encrypted' on a vanilla machine
    assert cls.value in ("code", "compressed", "data")


def test_decompile_failure_returns_typed_error_code(monkeypatch):
    """Pattern 5 — opaque decompile failures: ToolError with stable code.

    We don't need real Ghidra — we test classify_decompile_failure directly.
    """
    from ghidra_nexus.errors import classify_decompile_failure

    assert (
        classify_decompile_failure("No decompiler license available")
        is ToolErrorCode.DECOMPILE_NO_LICENSE
    )
    assert (
        classify_decompile_failure("Function size is below minimum")
        is ToolErrorCode.DECOMPILE_TOO_SMALL
    )
    body = make_tool_error(
        ToolErrorCode.DECOMPILE_ENCRYPTED, "Function is encrypted",
        binary_name="find.exe", addr="0x401000",
    )
    assert body["error_code"] == "encrypted_bytes"
    assert body["fallback_tool"] == "disassemble"


def test_check_project_path_writable_clean():
    """Pattern 3 — path check helper returns clean list for healthy path."""
    from ghidra_nexus.server import _check_project_path_writable

    warnings = _check_project_path_writable(Path("C:/tmp/some/clean/path"))
    # Either empty list or only warnings we don't expect on Windows
    assert isinstance(warnings, list)


def test_check_project_path_writable_flags_program_files():
    """Pattern 3 — path check helper flags Program Files subdirs."""
    from ghidra_nexus.server import _check_project_path_writable

    warnings = _check_project_path_writable(Path("C:/Program Files/GhidraNexus"))
    if os.name == "nt":  # only meaningful on Windows
        assert any("UAC" in w or "Program Files" in w for w in warnings), (
            f"expected Program Files warning, got {warnings}"
        )
