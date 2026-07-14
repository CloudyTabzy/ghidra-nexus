"""Unit tests for the survey_binary family — single-call binary triage snapshot.

These tests focus on the *MCP handler layer* (mcp_tools.survey_binary /
survey_binary_fast / survey_binary_full) and the GhidraTools wrapper,
using mocks so they can run without a live Ghidra JVM. The end-to-end
behaviour against a real Ghidra Program is covered by the integration
test in tests/integration/test_survey_binary.py.
"""

import asyncio
from unittest.mock import Mock

import pytest

from ghidra_nexus import mcp_tools
from ghidra_nexus.models import (
    SurveyBinaryResult,
    SurveyCallGraphSummary,
    SurveyMetadata,
    SurveyStatistics,
)


def _build_sample_survey_payload(*, mode: str = "full") -> dict:
    """A minimal valid SurveyBinaryResult payload for handler tests."""
    return {
        "ok": True,
        "mode": mode,
        "metadata": SurveyMetadata(
            path="C:/sample.exe",
            module="sample.exe",
            arch="64",
            base_address="0x140000000",
            image_size="0x10000",
            md5="0" * 32,
            sha256="0" * 64,
        ).model_dump(),
        "statistics": SurveyStatistics(
            total_functions=10,
            named_functions=5,
            library_functions=3,
            unnamed_functions=2,
            thunk_functions=0,
            total_strings=42,
            total_segments=4,
        ).model_dump(),
        "segments": [
            {
                "name": ".text",
                "start": "0x140001000",
                "end": "0x140005000",
                "size": "0x4000",
                "permissions": "r-x",
            }
        ],
        "entrypoints": [
            {"addr": "0x140001000", "name": "entry"},
        ],
        "interesting_strings": [],
        "interesting_functions": [],
        "imports_by_category": {
            "crypto": [],
            "network": [],
            "file_io": [],
            "process": [],
            "registry": [],
            "other": [],
        },
        "call_graph_summary": SurveyCallGraphSummary(
            total_edges=0,
            max_depth_estimate=None,
            root_functions=[],
            leaf_functions_count=0,
        ).model_dump(),
    }


def _make_program_info(*, analysis_complete: bool = True) -> Mock:
    """A Mock with the ProgramInfo fields the survey handler inspects."""
    pi = Mock()
    pi.name = "sample"
    pi.analysis_complete = analysis_complete
    pi.ghidra_analysis_complete = analysis_complete
    return pi


# ---------------------------------------------------------------------------
# survey_binary (backward-compat alias) and survey_binary_full
# ---------------------------------------------------------------------------


def test_survey_full_handler_validates_payload_with_pydantic(monkeypatch):
    """survey_binary_full runs via the executor and returns a typed result."""
    pi = _make_program_info()
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    payload = _build_sample_survey_payload(mode="full")
    fake_tools.survey_binary_full.return_value = SurveyBinaryResult.model_validate(
        payload
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr(mcp_tools, "GhidraTools", lambda _pi: fake_tools)

    submitted: dict = {}

    async def fake_submit(_pi, fn, **kwargs):
        submitted["called"] = True
        submitted["kwargs"] = kwargs
        return fn()

    monkeypatch.setattr(mcp_tools, "get_executor", lambda: Mock(submit=fake_submit))

    response = asyncio.run(
        mcp_tools.survey_binary_full(
            binary_name="sample", ctx=ctx, detail_level="standard"
        )
    )

    assert submitted["called"] is True
    assert submitted["kwargs"].get("write", False) is False
    assert "sample" in submitted["kwargs"]["task_id"]
    assert submitted["kwargs"]["task_id"].startswith("survey_full:")

    assert isinstance(response, SurveyBinaryResult)
    assert response.mode == "full"
    assert response.metadata.arch == "64"
    assert response.statistics.total_functions == 10


def test_survey_full_refuses_when_analysis_incomplete():
    """Refuse to run survey_binary_full while Ghidra is still analyzing.

    Phase 0.5.1: returns structured ToolError body (ok:false), not McpError.
    """
    from ghidra_nexus.errors import ProgramAccessError, ToolErrorCode

    pyghidra_context = Mock()

    def _get_program_info(name, *, require_analysis=True):
        if require_analysis:
            raise ProgramAccessError(
                ToolErrorCode.BINARY_ANALYZING,
                f"Analysis incomplete for binary '{name}'.",
                binary_name=name,
            )
        return _make_program_info(analysis_complete=False)

    pyghidra_context.get_program_info.side_effect = _get_program_info

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    result = asyncio.run(
        mcp_tools.survey_binary_full(
            binary_name="sample", ctx=ctx, detail_level="standard"
        )
    )

    assert isinstance(result, dict)
    assert result.get("ok") is False
    assert result.get("error_code") == "binary_analyzing"
    assert result.get("fallback_tool") == "analysis_status"
    hint = result.get("hint") or ""
    assert "survey_binary_fast" in hint or "analysis_status" in hint


def test_survey_full_forwards_minimal_detail_level(monkeypatch):
    """detail_level='minimal' must be passed through to the tool method."""
    pi = _make_program_info()
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    fake_tools.survey_binary_full.return_value = SurveyBinaryResult.model_validate(
        _build_sample_survey_payload(mode="full")
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr(mcp_tools, "GhidraTools", lambda _pi: fake_tools)

    captured: dict = {}

    async def fake_submit(_pi, fn, **kwargs):
        captured["task_id"] = kwargs.get("task_id", "")
        return fn()

    monkeypatch.setattr(mcp_tools, "get_executor", lambda: Mock(submit=fake_submit))

    asyncio.run(
        mcp_tools.survey_binary_full(
            binary_name="sample", ctx=ctx, detail_level="minimal"
        )
    )

    fake_tools.survey_binary_full.assert_called_once_with(detail_level="minimal")
    assert captured["task_id"].endswith(":minimal")


def test_survey_alias_routes_to_full(monkeypatch):
    """The original ``survey_binary`` tool remains a backward-compat alias for full."""
    pi = _make_program_info()
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    fake_tools.survey_binary_full.return_value = SurveyBinaryResult.model_validate(
        _build_sample_survey_payload(mode="full")
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr(mcp_tools, "GhidraTools", lambda _pi: fake_tools)

    async def fake_submit(_pi, fn, **kwargs):
        return fn()

    monkeypatch.setattr(mcp_tools, "get_executor", lambda: Mock(submit=fake_submit))

    response = asyncio.run(
        mcp_tools.survey_binary(binary_name="sample", ctx=ctx, detail_level="standard")
    )

    fake_tools.survey_binary_full.assert_called_once_with(detail_level="standard")
    assert response.mode == "full"


def test_survey_full_tool_rejects_invalid_detail_level():
    """The GhidraTools wrapper must validate detail_level itself."""
    fake_tools = mcp_tools.GhidraTools.__new__(mcp_tools.GhidraTools)
    fake_tools.program = Mock()
    with pytest.raises(ValueError, match="standard"):
        fake_tools.survey_binary_full(detail_level="bogus")


# ---------------------------------------------------------------------------
# survey_binary_fast
# ---------------------------------------------------------------------------


def test_survey_fast_runs_regardless_of_analysis_complete(monkeypatch):
    """survey_binary_fast does NOT wait for analysis — works on partial programs."""
    pi = _make_program_info(analysis_complete=False)  # NOT analyzed
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    payload = _build_sample_survey_payload(mode="fast")
    payload["note"] = "pre-analysis: Ghidra auto-analysis has not run yet."
    fake_tools.survey_binary_fast.return_value = SurveyBinaryResult.model_validate(
        payload
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr(mcp_tools, "GhidraTools", lambda _pi: fake_tools)

    submitted: dict = {}

    async def fake_submit(_pi, fn, **kwargs):
        submitted["called"] = True
        submitted["kwargs"] = kwargs
        return fn()

    monkeypatch.setattr(mcp_tools, "get_executor", lambda: Mock(submit=fake_submit))

    # Should NOT raise even though analysis_complete is False.
    response = asyncio.run(
        mcp_tools.survey_binary_fast(binary_name="sample", ctx=ctx)
    )

    assert submitted["called"] is True
    assert submitted["kwargs"].get("write", False) is False
    assert submitted["kwargs"]["task_id"] == "survey_fast:sample"

    assert isinstance(response, SurveyBinaryResult)
    assert response.mode == "fast"
    assert "pre-analysis" in (response.note or "")


def test_survey_fast_does_not_refuse_on_incomplete_analysis(monkeypatch):
    """Explicitly assert: fast survey never raises on incomplete analysis."""
    pi = _make_program_info(analysis_complete=False)
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    fake_tools.survey_binary_fast.return_value = SurveyBinaryResult.model_validate(
        _build_sample_survey_payload(mode="fast")
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr(mcp_tools, "GhidraTools", lambda _pi: fake_tools)

    async def fake_submit(_pi, fn, **kwargs):
        return fn()

    monkeypatch.setattr(mcp_tools, "get_executor", lambda: Mock(submit=fake_submit))

    # Run many times to make absolutely sure.
    for _ in range(5):
        response = asyncio.run(
            mcp_tools.survey_binary_fast(binary_name="sample", ctx=ctx)
        )
        assert response.mode == "fast"


def test_survey_fast_does_not_call_full(monkeypatch):
    """survey_binary_fast must call GhidraTools.survey_binary_fast, not full."""
    pi = _make_program_info()
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    fake_tools.survey_binary_fast.return_value = SurveyBinaryResult.model_validate(
        _build_sample_survey_payload(mode="fast")
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr(mcp_tools, "GhidraTools", lambda _pi: fake_tools)

    async def fake_submit(_pi, fn, **kwargs):
        return fn()

    monkeypatch.setattr(mcp_tools, "get_executor", lambda: Mock(submit=fake_submit))

    asyncio.run(mcp_tools.survey_binary_fast(binary_name="sample", ctx=ctx))

    fake_tools.survey_binary_fast.assert_called_once_with()
    fake_tools.survey_binary_full.assert_not_called()


# ---------------------------------------------------------------------------
# Pydantic model contract
# ---------------------------------------------------------------------------


def test_survey_result_pydantic_round_trip():
    """The Pydantic model accepts a full raw dict and round-trips cleanly."""
    payload = _build_sample_survey_payload(mode="full")
    result = SurveyBinaryResult.model_validate(payload)
    again = SurveyBinaryResult.model_validate(result.model_dump())
    assert again == result
    assert again.metadata.path == "C:/sample.exe"
    assert again.statistics.total_functions == 10
    assert again.segments[0].permissions == "r-x"
    assert again.mode == "full"


def test_survey_result_default_mode_is_full():
    """A payload without 'mode' still validates and defaults to mode='full'."""
    payload = _build_sample_survey_payload()
    del payload["mode"]
    result = SurveyBinaryResult.model_validate(payload)
    assert result.mode == "full"


def test_survey_result_fast_mode_validates():
    """A 'fast' mode payload validates and exposes pre-analysis fields."""
    payload = _build_sample_survey_payload(mode="fast")
    payload["note"] = "pre-analysis: ..."
    result = SurveyBinaryResult.model_validate(payload)
    assert result.mode == "fast"
    assert "pre-analysis" in (result.note or "")
