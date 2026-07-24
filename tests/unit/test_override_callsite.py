"""Unit tests for override_callsite_signature (executor path, mocked GhidraTools)."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from ghidra_nexus.errors import ToolErrorCode
from ghidra_nexus.mcp_tools import _ToolRecoverable, override_callsite_signature
from ghidra_nexus.models import CallsiteOverrideResult


def _mock_executor(monkeypatch, side_effect=None, capture=None):
    """Replace get_executor().submit with an async that runs the callable."""
    executor = Mock()

    async def submit(program_info, fn, *args, write=False, task_id=None, **kwargs):
        if capture is not None:
            capture["write"] = write
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


def _fake_result() -> CallsiteOverrideResult:
    return CallsiteOverrideResult(
        function_name="sub_887280",
        function_address="0x887280",
        call_site="0x8872AC",
        applied_signature="int __thiscall Lock(void *this, int flags)",
        verified=True,
    )


@pytest.mark.asyncio
async def test_override_happy_path(monkeypatch):
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.override_callsite_signature.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await override_callsite_signature(
        binary_name="sample",
        function="sub_887280",
        call_site="0x8872AC",
        signature="int __thiscall Lock(void *this, int flags)",
        ctx=ctx,
    )

    fake_tools.override_callsite_signature.assert_called_once()
    assert response.verified is True
    assert response.call_site == "0x8872AC"


@pytest.mark.asyncio
async def test_override_dispatches_as_write(monkeypatch):
    """Overrides mutate the program — must go through the write path."""
    capture = {}
    _mock_executor(monkeypatch, capture=capture)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.override_callsite_signature.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    await override_callsite_signature(
        binary_name="sample",
        function="sub_887280",
        call_site="0x8872AC",
        signature="int __thiscall Lock(void *this, int flags)",
        ctx=ctx,
    )
    assert capture.get("write") is True, "override must use executor write=True"


@pytest.mark.asyncio
async def test_override_empty_signature_is_invalid_params(monkeypatch):
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    response = await override_callsite_signature(
        binary_name="sample",
        function="sub_887280",
        call_site="0x8872AC",
        signature="  ",
        ctx=ctx,
    )
    assert response["ok"] is False
    assert response["error_code"] == "invalid_params"


@pytest.mark.asyncio
async def test_override_handles_missing_binary(monkeypatch):
    _mock_executor(monkeypatch)
    ctx, pyghidra_context = _mock_ctx()
    pyghidra_context.get_program_info.side_effect = _ToolRecoverable(
        ToolErrorCode.BINARY_NOT_FOUND, "Binary 'sample' not in project"
    )

    response = await override_callsite_signature(
        binary_name="sample",
        function="sub_887280",
        call_site="0x8872AC",
        signature="int __cdecl Lock(int flags)",
        ctx=ctx,
    )
    assert response["ok"] is False
    assert response["error_code"] == "binary_not_found"


@pytest.mark.asyncio
async def test_override_handles_unknown_symbol(monkeypatch):
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.override_callsite_signature.side_effect = ValueError(
        "Function or symbol 'foo' not found."
    )
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await override_callsite_signature(
        binary_name="sample",
        function="foo",
        call_site="0x8872AC",
        signature="int __cdecl Lock(int flags)",
        ctx=ctx,
    )
    assert response["ok"] is False
    assert response["error_code"] == "symbol_not_found"
