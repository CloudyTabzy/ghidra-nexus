"""Unit tests for disassemble_call_site (executor path, mocked GhidraTools)."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest

from ghidra_nexus.errors import ToolErrorCode
from ghidra_nexus.mcp_tools import _ToolRecoverable, disassemble_call_site
from ghidra_nexus.models import (
    CallSiteAnalysisResult,
    CallSiteInfo,
    StackArgEvidence,
)


def _mock_executor(monkeypatch, side_effect=None):
    """Replace get_executor().submit with an async that runs the callable."""
    executor = Mock()

    async def submit(program_info, fn, *args, write=False, task_id=None, **kwargs):
        if side_effect is not None:
            return await side_effect(program_info, fn, write=write, task_id=task_id)
        return fn()

    executor.submit = submit
    monkeypatch.setattr("ghidra_nexus.mcp_tools.get_executor", lambda: executor)
    return executor


def _fake_result() -> CallSiteAnalysisResult:
    return CallSiteAnalysisResult(
        function_name="sub_887280",
        function_address="0x887280",
        binary_name="sample",
        call_sites=[
            CallSiteInfo(
                address="0x8872AC",
                instruction="CALL EAX",
                is_indirect=True,
                stack_args=[
                    StackArgEvidence(
                        slot_offset=0,
                        source="eax",
                        resolved_source=None,
                        written_at="0x8872A0",
                        write_kind="push",
                    )
                ],
                ecx_source="[eax]",
                inferred_convention="__thiscall?",
                confidence="medium",
            )
        ],
        total_call_sites=1,
    )


def _mock_ctx(program_info=None):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = program_info or Mock()
    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    return ctx, pyghidra_context


@pytest.mark.asyncio
async def test_disassemble_call_site_happy_path(monkeypatch):
    """Tool returns call-site evidence on success."""
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.analyze_call_sites.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await disassemble_call_site(binary_name="sample", function="sub_887280", ctx=ctx)

    fake_tools.analyze_call_sites.assert_called_once()
    assert response.function_name == "sub_887280"
    assert response.total_call_sites == 1
    assert response.call_sites[0].address == "0x8872AC"
    assert response.call_sites[0].stack_args[0].slot_offset == 0
    assert response.cached is False
    assert response.page is not None


@pytest.mark.asyncio
async def test_disassemble_call_site_offloads_to_executor(monkeypatch):
    """Tool dispatches through ghidra_executor, never the asyncio thread."""
    called = asyncio.Event()

    async def submit(program_info, fn, *args, write=False, task_id=None, **kwargs):
        called.set()
        return fn()

    _mock_executor(monkeypatch, side_effect=submit)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.analyze_call_sites.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    await disassemble_call_site(binary_name="sample", function="sub_887280", ctx=ctx)
    assert called.is_set(), "tool bypassed executor — should never happen"


@pytest.mark.asyncio
async def test_disassemble_call_site_handles_missing_binary(monkeypatch):
    """Missing binary returns a structured error, not an exception."""
    _mock_executor(monkeypatch)
    ctx, pyghidra_context = _mock_ctx()
    pyghidra_context.get_program_info.side_effect = _ToolRecoverable(
        ToolErrorCode.BINARY_NOT_FOUND, "Binary 'sample' not in project"
    )

    response = await disassemble_call_site(binary_name="sample", function="sub_887280", ctx=ctx)
    assert response["ok"] is False
    assert response["error_code"] == "binary_not_found"
    assert response["hint"]


@pytest.mark.asyncio
async def test_disassemble_call_site_handles_unknown_symbol(monkeypatch):
    """Unknown function maps to symbol_not_found with a hint."""
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.analyze_call_sites.side_effect = ValueError("Function or symbol 'foo' not found.")
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await disassemble_call_site(binary_name="sample", function="foo", ctx=ctx)
    assert response["ok"] is False
    assert response["error_code"] == "symbol_not_found"
    assert response["hint"]


@pytest.mark.asyncio
async def test_disassemble_call_site_cache_hit_skips_executor(monkeypatch):
    """Second call for the same function is served from the notebook cache."""
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.analyze_call_sites.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    first = await disassemble_call_site(binary_name="sample", function="sub_887280", ctx=ctx)
    assert first.cached is False

    second = await disassemble_call_site(binary_name="sample", function="sub_887280", ctx=ctx)
    assert second.cached is True
    assert second.call_sites[0].address == "0x8872AC"
    # Executor path (GhidraTools) was hit exactly once — the first call.
    assert fake_tools.analyze_call_sites.call_count == 1


def test_register_lazy_tools_registers_only_wake_and_status():
    """streamable-http cold start exposes wake_ghidra + ghidra_status only."""
    from ghidra_nexus import mcp_tools

    server = Mock()
    mcp_tools._register_lazy_tools(server)
    names = {call.kwargs["name"] for call in server.add_tool.call_args_list}
    assert names == {"wake_ghidra", "ghidra_status"}
