"""Unit tests for analysis_status enrichment (Phase 0.5.1)."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from ghidra_nexus.mcp_tools import analysis_status
from ghidra_nexus.models import ProgramInfo


@pytest.mark.asyncio
async def test_analysis_status_uses_enriched_function_count(monkeypatch, tmp_path):
    pe = tmp_path / "find.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 64)

    raw = ProgramInfo(
        name="find.exe",
        file_path=str(pe),
        load_time=1.0,
        analysis_complete=True,
        metadata={"function_count": 27, "sha256": "abc", "entropy_summary": "normal"},
        code_indexed=False,
        strings_indexed=False,
        analysis_state="complete",
        function_count=27,
        sha256="abc",
        entropy_summary="normal",
    )

    pyghidra_context = Mock()
    pyghidra_context.list_project_binary_infos.return_value = [raw]
    pyghidra_context.project_path = tmp_path
    pyghidra_context.nexus_data_dir = tmp_path / "nexus"
    pyghidra_context.programs = {}
    pyghidra_context._programs_lock = __import__("threading").Lock()
    pyghidra_context.ensure_entropy_summary = Mock(return_value="normal")

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr(
        "ghidra_nexus.server._check_project_path_writable",
        lambda _p: [],
    )

    result = await analysis_status(ctx)
    assert len(result.binaries) == 1
    b = result.binaries[0]
    assert b.function_count == 27
    assert b.sha256 == "abc"
    assert b.entropy_summary == "normal"
    assert b.analysis_state == "complete"
    assert b.path_exists is True
    assert "section_health" in b.recommended_tools or "survey_binary_full" in b.recommended_tools
    assert isinstance(result.path_warnings, list)


@pytest.mark.asyncio
async def test_analysis_status_zero_functions_recommends_section_health(monkeypatch, tmp_path):
    raw = ProgramInfo(
        name="packed.exe",
        file_path=None,
        load_time=None,
        analysis_complete=True,
        metadata={},
        code_indexed=False,
        strings_indexed=False,
        function_count=0,
        entropy_summary="encrypted",
    )
    pyghidra_context = Mock()
    pyghidra_context.list_project_binary_infos.return_value = [raw]
    pyghidra_context.project_path = tmp_path
    pyghidra_context.nexus_data_dir = tmp_path / "nexus"
    pyghidra_context.programs = {}
    pyghidra_context._programs_lock = __import__("threading").Lock()

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    monkeypatch.setattr(
        "ghidra_nexus.server._check_project_path_writable",
        lambda _p: ["uac warning"],
    )

    result = await analysis_status(ctx)
    b = result.binaries[0]
    assert b.function_count == 0
    assert "section_health" in b.recommended_tools
    assert result.path_warnings == ["uac warning"]


@pytest.mark.asyncio
async def test_analysis_status_live_count_from_programs(monkeypatch, tmp_path):
    from ghidra_nexus.context import PyGhidraContext

    raw = ProgramInfo(
        name="live.exe",
        file_path=None,
        load_time=None,
        analysis_complete=True,
        metadata={},
        code_indexed=True,
        strings_indexed=True,
        function_count=0,  # list path stale
    )
    live = Mock()
    live.entropy_summary = "mixed"
    live.entropy_computed = True
    live.cached_sha256 = "deadbeef"
    live.file_path = None
    live.metadata = {}
    live.program = Mock()

    pyghidra_context = Mock()
    pyghidra_context.list_project_binary_infos.return_value = [raw]
    pyghidra_context.project_path = tmp_path
    pyghidra_context.nexus_data_dir = tmp_path / "nexus"
    pyghidra_context.programs = {"live.exe": live}
    pyghidra_context._programs_lock = __import__("threading").Lock()
    pyghidra_context.ensure_entropy_summary = Mock(return_value="mixed")

    monkeypatch.setattr(PyGhidraContext, "_safe_function_count", staticmethod(lambda _pi: 42))
    monkeypatch.setattr(PyGhidraContext, "_safe_sha256", staticmethod(lambda _pi: "deadbeef"))
    monkeypatch.setattr(
        "ghidra_nexus.server._check_project_path_writable",
        lambda _p: [],
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    result = await analysis_status(ctx)
    b = result.binaries[0]
    assert b.function_count == 42
    assert b.sha256 == "deadbeef"
    assert b.entropy_summary == "mixed"
