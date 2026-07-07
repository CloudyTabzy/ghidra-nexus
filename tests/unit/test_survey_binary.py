"""Unit tests for survey_binary — single-call binary triage snapshot.

These tests focus on the *MCP handler layer* (mcp_tools.survey_binary) and
the GhidraTools wrapper, using mocks so they can run without a live Ghidra
JVM. The end-to-end behaviour against a real Ghidra Program is covered by
the integration test in tests/integration/test_survey_binary.py.
"""

import asyncio
from unittest.mock import Mock

import pytest
from mcp.shared.exceptions import McpError

from pyghidra_mcp import mcp_tools
from pyghidra_mcp.models import (
    SurveyBinaryResult,
    SurveyMetadata,
    SurveyStatistics,
)


def _build_sample_survey_payload() -> dict:
    """A minimal valid SurveyBinaryResult payload for handler tests."""
    return {
        "ok": True,
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
        "call_graph_summary": {
            "total_edges": 0,
            "max_depth_estimate": None,
            "root_functions": [],
            "leaf_functions_count": 0,
        },
    }


def _make_program_info(*, analysis_complete: bool = True) -> Mock:
    """A Mock with the ProgramInfo fields the survey handler inspects."""
    pi = Mock()
    pi.name = "sample"
    pi.analysis_complete = analysis_complete
    pi.ghidra_analysis_complete = analysis_complete
    return pi


def test_survey_handler_validates_payload_with_pydantic(monkeypatch):
    """Handler must run via the executor and return a typed SurveyBinaryResult."""
    pi = _make_program_info()
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    payload = _build_sample_survey_payload()
    fake_tools.survey_binary.return_value = SurveyBinaryResult.model_validate(payload)

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
        mcp_tools.survey_binary(binary_name="sample", ctx=ctx, detail_level="standard")
    )

    assert submitted["called"] is True
    assert submitted["kwargs"].get("write", False) is False
    # task_id is human-readable and namespaced
    assert "sample" in submitted["kwargs"]["task_id"]
    assert submitted["kwargs"]["task_id"].startswith("survey:")

    # Handler validates via Pydantic — return type is a SurveyBinaryResult.
    assert isinstance(response, SurveyBinaryResult)
    assert response.metadata.arch == "64"
    assert response.statistics.total_functions == 10


def test_survey_handler_refuses_when_analysis_incomplete():
    """Refuse to run survey while Ghidra is still analyzing the program."""
    pi = _make_program_info(analysis_complete=False)
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    with pytest.raises(McpError) as excinfo:
        asyncio.run(
            mcp_tools.survey_binary(
                binary_name="sample", ctx=ctx, detail_level="standard"
            )
        )

    msg = str(excinfo.value)
    assert "analysis" in msg.lower() or "progress" in msg.lower()


def test_survey_handler_forwards_minimal_detail_level(monkeypatch):
    """detail_level='minimal' must be passed through to the tool method."""
    pi = _make_program_info()
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    fake_tools.survey_binary.return_value = SurveyBinaryResult.model_validate(
        _build_sample_survey_payload()
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
        mcp_tools.survey_binary(binary_name="sample", ctx=ctx, detail_level="minimal")
    )

    fake_tools.survey_binary.assert_called_once_with(detail_level="minimal")
    assert captured["task_id"].endswith(":minimal")


@pytest.mark.asyncio
async def test_survey_handler_does_not_run_concurrent_with_decompile(monkeypatch):
    """Two concurrent survey/decompile calls must not interleave on the executor."""
    pi = _make_program_info()
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = pi

    fake_tools = Mock()
    fake_tools.survey_binary.return_value = SurveyBinaryResult.model_validate(
        _build_sample_survey_payload()
    )
    fake_tools.decompile_function_by_name_or_addr.return_value = Mock(
        code="", name="entry", error=None
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    monkeypatch.setattr(mcp_tools, "GhidraTools", lambda _pi: fake_tools)

    started = asyncio.Event()
    release = asyncio.Event()
    in_progress = {"decompile": False, "survey": False}

    async def fake_submit(_pi, fn, **kwargs):
        # Mark which kind of call is being made and simulate work
        is_decompile = "decompile" in kwargs.get("task_id", "")
        in_progress["decompile" if is_decompile else "survey"] = True
        try:
            if not is_decompile:
                started.set()
                await release.wait()
            return fn()
        finally:
            in_progress["decompile" if is_decompile else "survey"] = False

    monkeypatch.setattr(mcp_tools, "get_executor", lambda: Mock(submit=fake_submit))

    survey_task = asyncio.create_task(
        mcp_tools.survey_binary(
            binary_name="sample", ctx=ctx, detail_level="standard"
        )
    )
    await_started = asyncio.create_task(started.wait())

    # While the survey is blocked in the executor, run a decompile through
    # the same executor — they must NOT execute concurrently.
    decompile_task = asyncio.create_task(
        mcp_tools.decompile_function(
            binary_name="sample", name_or_address="entry", ctx=ctx, timeout_sec=10
        )
    )

    # Give the decompile task a chance to run; the executor funnel should
    # make it wait for the survey to finish.
    try:
        await asyncio.wait_for(await_started, timeout=0.5)
    except asyncio.TimeoutError:
        pass

    assert in_progress["survey"] is True
    # The decompile call should be queued (not yet running) because the
    # survey is in flight.
    assert in_progress["decompile"] is False

    release.set()
    survey_result, _ = await asyncio.gather(survey_task, decompile_task)

    assert isinstance(survey_result, SurveyBinaryResult)
    assert in_progress["decompile"] is False


def test_survey_tool_rejects_invalid_detail_level():
    """The GhidraTools wrapper must validate detail_level itself."""
    fake_tools = mcp_tools.GhidraTools.__new__(mcp_tools.GhidraTools)
    fake_tools.program = Mock()
    with pytest.raises(ValueError, match="standard"):
        fake_tools.survey_binary(detail_level="bogus")


def test_survey_result_pydantic_round_trip():
    """The Pydantic model accepts a full raw dict and round-trips cleanly."""
    payload = _build_sample_survey_payload()
    result = SurveyBinaryResult.model_validate(payload)
    again = SurveyBinaryResult.model_validate(result.model_dump())
    assert again == result
    assert again.metadata.path == "C:/sample.exe"
    assert again.statistics.total_functions == 10
    assert again.segments[0].permissions == "r-x"
