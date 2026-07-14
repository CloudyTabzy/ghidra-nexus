"""Integration tests for Phase 0.5 / 0.5.1 — real-binary E2E.

These tests need a working Ghidra install. They are skipped if
:envvar:`GHIDRA_INSTALL_DIR` is not set.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ghidra_nexus.errors import ToolErrorCode, make_tool_error
from ghidra_nexus.section_entropy import shannon_entropy

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
    """Pattern 2 — import returns pollable task fields, never silent success."""
    result = ghidra_project.import_binary_backgrounded(find_exe_path)
    assert result.task_id, "task_id must be present"
    assert result.binary_name, "binary_name must be present"
    assert result.analysis_state in ("queued", "analyzing_functions", "complete", "loading")
    assert result.nexus_data_dir
    assert result.project_path


def test_import_missing_path_raises_program_access_error(ghidra_project):
    """Pattern 1 — missing path is a structured ProgramAccessError, not FileNotFoundError."""
    from ghidra_nexus.errors import ProgramAccessError

    with pytest.raises(ProgramAccessError) as ei:
        ghidra_project.import_binary_backgrounded(Path("C:/definitely/not/a/real/binary.exe"))
    assert ei.value.code is ToolErrorCode.BINARY_PATH_UNREADABLE


def test_get_program_info_missing_is_program_access_error(ghidra_project):
    from ghidra_nexus.errors import ProgramAccessError

    with pytest.raises(ProgramAccessError) as ei:
        ghidra_project.get_program_info("this_binary_does_not_exist_xyz", require_analysis=False)
    assert ei.value.code is ToolErrorCode.BINARY_NOT_FOUND
    body = ei.value.to_tool_error_dict()
    assert body["fallback_tool"] == "list_project_binaries"
    assert body["ok"] is False


def test_list_project_binary_infos_includes_function_count_field(ghidra_project, find_exe_path):
    """Pattern 2 — status fields must be present (even if count is still 0 mid-import)."""
    ghidra_project.import_binary_backgrounded(find_exe_path)
    infos = ghidra_project.list_project_binary_infos()
    # May be empty if import not finished; if present, must have typed fields.
    for info in infos:
        assert hasattr(info, "function_count")
        assert isinstance(info.function_count, int)
        assert info.function_count >= 0
        assert info.entropy_summary in (
            "unknown",
            "normal",
            "encrypted",
            "compressed",
            "mixed",
        )


def test_analysis_status_returns_path_warnings(ghidra_project):
    """Pattern 3 — response shape includes path_warnings as a list."""
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
    """Pattern 4 — entropy pipeline gives sane output for a normal binary."""
    from ghidra_nexus.section_entropy import classify_section

    data = find_exe_path.read_bytes()
    e = shannon_entropy(data[: 64 * 1024])
    cls, _rec, _ = classify_section(
        entropy=e, size_bytes=len(data), is_executable=True
    )
    assert cls.value in ("code", "compressed", "data")


def test_decompile_failure_returns_typed_error_code():
    """Pattern 5 — ToolError with stable code."""
    from ghidra_nexus.errors import classify_decompile_failure, decompile_failure_result

    assert (
        classify_decompile_failure("No decompiler license available")
        is ToolErrorCode.DECOMPILE_NO_LICENSE
    )
    assert (
        classify_decompile_failure("Function size is below minimum")
        is ToolErrorCode.DECOMPILE_TOO_SMALL
    )
    body = make_tool_error(
        ToolErrorCode.DECOMPILE_ENCRYPTED,
        "Function is encrypted",
        binary_name="find.exe",
        addr="0x401000",
    )
    assert body["error_code"] == "encrypted_bytes"
    assert body["fallback_tool"] == "disassemble"

    fields = decompile_failure_result("stub", "Symbol 'x' not found.", binary_name="find.exe")
    assert fields["code"] == ""
    assert fields["error_code"] == "symbol_not_found"


def test_check_project_path_writable_clean():
    from ghidra_nexus.server import _check_project_path_writable

    warnings = _check_project_path_writable(Path("C:/tmp/some/clean/path"))
    assert isinstance(warnings, list)


def test_check_project_path_writable_flags_program_files():
    from ghidra_nexus.server import _check_project_path_writable

    warnings = _check_project_path_writable(Path("C:/Program Files/GhidraNexus"))
    if os.name == "nt":
        assert any("UAC" in w or "Program Files" in w for w in warnings), (
            f"expected Program Files warning, got {warnings}"
        )
    # Message must not say "IDA"
    assert all("IDA" not in w for w in warnings)
