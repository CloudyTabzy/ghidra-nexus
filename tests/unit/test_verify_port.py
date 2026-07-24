"""Unit tests for verify_port (executor path, mocked GhidraTools)."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest

from ghidra_nexus.errors import ToolErrorCode
from ghidra_nexus.mcp_tools import _ToolRecoverable, verify_port
from ghidra_nexus.models import VerifyPortCheck, VerifyPortResult


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


def _fake_result(verdict: str = "pass") -> VerifyPortResult:
    return VerifyPortResult(
        target="sub_887280",
        proposed_signature="int __thiscall Lock(int flags, uint count)",
        binary_name="sample",
        addr="0x887280",
        checks=[
            VerifyPortCheck(
                name="calling_convention",
                expected="__thiscall",
                actual="__thiscall",
                status="pass",
            )
        ],
        verdict=verdict,
        hint="Fix the failing checks." if verdict == "fail" else None,
    )


@pytest.mark.asyncio
async def test_verify_port_happy_path(monkeypatch):
    """Tool returns the verification verdict on success."""
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.verify_port.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await verify_port(
        binary_name="sample",
        target="sub_887280",
        signature="int __thiscall Lock(int flags, uint count)",
        ctx=ctx,
    )

    fake_tools.verify_port.assert_called_once()
    assert response.verdict == "pass"
    assert response.checks[0].name == "calling_convention"


@pytest.mark.asyncio
async def test_verify_port_offloads_to_executor(monkeypatch):
    """Tool dispatches through ghidra_executor, never the asyncio thread."""
    called = asyncio.Event()

    async def submit(program_info, fn, *args, write=False, task_id=None, **kwargs):
        called.set()
        return fn()

    _mock_executor(monkeypatch, side_effect=submit)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.verify_port.return_value = _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    await verify_port(
        binary_name="sample",
        target="sub_887280",
        signature="int __cdecl Lock(int flags)",
        ctx=ctx,
    )
    assert called.is_set(), "tool bypassed executor — should never happen"


@pytest.mark.asyncio
async def test_verify_port_empty_signature_is_invalid_params(monkeypatch):
    """Empty signature fails fast with invalid_params — no executor call."""
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    response = await verify_port(binary_name="sample", target="sub_887280", signature="  ", ctx=ctx)
    assert response["ok"] is False
    assert response["error_code"] == "invalid_params"
    assert response["hint"]


@pytest.mark.asyncio
async def test_verify_port_unparseable_signature_is_invalid_params(monkeypatch):
    """A signature Ghidra can't parse maps to invalid_params."""
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.verify_port.side_effect = ValueError("Could not parse signature 'not a prototype'")
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await verify_port(
        binary_name="sample", target="sub_887280", signature="not a prototype", ctx=ctx
    )
    assert response["ok"] is False
    assert response["error_code"] == "invalid_params"
    assert response["hint"]


@pytest.mark.asyncio
async def test_verify_port_handles_missing_binary(monkeypatch):
    """Missing binary returns a structured error, not an exception."""
    _mock_executor(monkeypatch)
    ctx, pyghidra_context = _mock_ctx()
    pyghidra_context.get_program_info.side_effect = _ToolRecoverable(
        ToolErrorCode.BINARY_NOT_FOUND, "Binary 'sample' not in project"
    )

    response = await verify_port(
        binary_name="sample",
        target="sub_887280",
        signature="int __cdecl Lock(int flags)",
        ctx=ctx,
    )
    assert response["ok"] is False
    assert response["error_code"] == "binary_not_found"
    assert response["hint"]


@pytest.mark.asyncio
async def test_verify_port_handles_unknown_symbol(monkeypatch):
    """Unknown function maps to symbol_not_found with a hint."""
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.verify_port.side_effect = ValueError("Function or symbol 'foo' not found.")
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    response = await verify_port(
        binary_name="sample",
        target="foo",
        signature="int __cdecl Lock(int flags)",
        ctx=ctx,
    )
    assert response["ok"] is False
    assert response["error_code"] == "symbol_not_found"
    assert response["hint"]


@pytest.mark.asyncio
async def test_verify_port_records_verdict_and_surfaces_prior(monkeypatch):
    """Verdicts persist in the notebook; later runs see the prior one."""
    _mock_executor(monkeypatch)
    ctx, _ = _mock_ctx()

    fake_tools = Mock()
    fake_tools.verify_port.side_effect = lambda *a, **k: _fake_result()
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _p: fake_tools)

    sig = "int __thiscall Lock(int flags, uint count)"
    first = await verify_port(binary_name="sample", target="sub_887280", signature=sig, ctx=ctx)
    assert first.prior_verdict is None

    second = await verify_port(binary_name="sample", target="sub_887280", signature=sig, ctx=ctx)
    assert second.prior_verdict is not None
    assert second.prior_verdict["verdict"] == "pass"
    assert second.prior_verdict["signature"] == sig

    # State-drift: changing the proposed signature surfaces the diff.
    third = await verify_port(
        binary_name="sample",
        target="sub_887280",
        signature="int __cdecl Lock(int flags)",
        ctx=ctx,
    )
    assert third.prior_verdict is not None
    assert any("different signature" in w for w in third.warnings)

    # The verdict row is actually in the notebook.
    import ghidra_nexus.mcp_tools as _mt

    nb = await _mt._get_notebook(None)
    b = nb.binaries.get("sample")
    assert b is not None
    assert nb.port_verifications.count_for_binary(b["id"]) == 3
