"""Unit tests for generate_hook_stub (executor path, mocked GhidraTools)."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest

from ghidra_nexus.errors import ToolErrorCode
from ghidra_nexus.mcp_tools import _ToolRecoverable, generate_hook_stub
from ghidra_nexus.models import HookStubResult


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


def _mock_ctx():
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()
    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    return ctx, pyghidra_context


def _fake_result() -> HookStubResult:
    return HookStubResult(
        target="sub_887280",
        language="zig",
        convention="thiscall",
        stub=(
            "pub const sub_887280_fn = *const fn (\n"
            "    this: *anyopaque,\n"
            ") callconv(.thiscall) i32;"
        ),
        clobbered_non_volatile=["ebx"],
        binary_name="sample",
    )


@pytest.mark.asyncio
async def test_generate_hook_stub_happy_path(monkeypatch):
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.generate_hook_stub.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await generate_hook_stub(
        binary_name="sample", target="sub_887280", call_site="0x8872AC", ctx=ctx
    )

    fake_tools.generate_hook_stub.assert_called_once()
    assert response.convention == "thiscall"
    assert "callconv(.thiscall)" in response.stub
    assert response.clobbered_non_volatile == ["ebx"]


@pytest.mark.asyncio
async def test_generate_hook_stub_offloads_to_executor(monkeypatch):
    called = asyncio.Event()

    async def submit(program_info, fn, *args, write=False, task_id=None, **kwargs):
        called.set()
        return fn()

    _mock_executor(monkeypatch, side_effect=submit)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.generate_hook_stub.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    await generate_hook_stub(binary_name="sample", target="sub_887280", ctx=ctx)
    assert called.is_set(), "tool bypassed executor — should never happen"


@pytest.mark.asyncio
async def test_generate_hook_stub_bad_language_is_invalid_params(monkeypatch):
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.generate_hook_stub.side_effect = ValueError(
        "Unsupported language 'rust' (expected 'zig' or 'c')"
    )
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await generate_hook_stub(
        binary_name="sample", target="sub_887280", language="rust", ctx=ctx
    )
    assert response["ok"] is False
    assert response["error_code"] == "invalid_params"


@pytest.mark.asyncio
async def test_generate_hook_stub_handles_missing_binary(monkeypatch):
    _mock_executor(monkeypatch)
    ctx, pyghidra_context = _mock_ctx()
    pyghidra_context.get_program_info.side_effect = _ToolRecoverable(
        ToolErrorCode.BINARY_NOT_FOUND, "Binary 'sample' not in project"
    )

    response = await generate_hook_stub(
        binary_name="sample", target="sub_887280", ctx=ctx
    )
    assert response["ok"] is False
    assert response["error_code"] == "binary_not_found"


@pytest.mark.asyncio
async def test_generate_hook_stub_handles_unknown_symbol(monkeypatch):
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.generate_hook_stub.side_effect = ValueError(
        "Function or symbol 'foo' not found."
    )
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await generate_hook_stub(binary_name="sample", target="foo", ctx=ctx)
    assert response["ok"] is False
    assert response["error_code"] == "symbol_not_found"
