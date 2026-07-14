"""Unit tests for the Phase 6 MCP tool: ``notebook_query_expand``.

These cover:
- ``slm_disabled`` when ``NEXUS_SLM_MODEL`` is unset
- ``binary_not_found`` when the binary is missing
- ``slm_failed`` when the SLM raises
- Success path with a mocked SLM

The actual SLM invocation is exercised in the integration suite
(real Qwen model on a real binary). These tests prove the wiring.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from ghidra_nexus.mcp_tools import notebook_query_expand
from ghidra_nexus.slm import ExpandedQuery


def _fresh_context():
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()
    pyghidra_context.nexus_data_dir = None
    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    return ctx


@pytest.mark.asyncio
async def test_notebook_query_expand_disabled_when_no_env(monkeypatch):
    """Without NEXUS_SLM_MODEL, returns slm_disabled with fallback_tool=search_code."""
    monkeypatch.delenv("NEXUS_SLM_MODEL", raising=False)
    ctx = _fresh_context()

    # Provide a notebook that returns a binary, so we get past the binary
    # lookup and into the SLM-disabled branch.
    from ghidra_nexus.mcp_tools import _get_notebook

    nb = await _get_notebook()
    nb.binaries.upsert(name="find.exe", sha256="a" * 64)

    response = await notebook_query_expand(
        ctx=ctx, binary_name="find.exe", query="connect network"
    )
    assert response["ok"] is False
    assert response["error_code"] == "slm_disabled"
    assert response["fallback_tool"] == "search_code"
    assert "NEXUS_SLM_MODEL" in response["message"]


@pytest.mark.asyncio
async def test_notebook_query_expand_disabled_when_trans_unavailable(monkeypatch):
    """When the SLM is configured but transformers/torch is missing, the tool
    must report ``slm_disabled`` rather than raising an ImportError.

    The :func:`is_available` helper returns False when transformers is
    unavailable; the tool respects that.
    """
    monkeypatch.setenv("NEXUS_SLM_MODEL", "Qwen/Qwen2.5-Coder-1.5B-Instruct")
    monkeypatch.setattr("ghidra_nexus.slm.is_available", lambda: False)

    from ghidra_nexus.mcp_tools import _get_notebook
    nb = await _get_notebook()
    nb.binaries.upsert(name="find.exe", sha256="a" * 64)

    ctx = _fresh_context()
    response = await notebook_query_expand(
        ctx=ctx, binary_name="find.exe", query="x"
    )
    assert response["ok"] is False
    assert response["error_code"] == "slm_disabled"


@pytest.mark.asyncio
async def test_notebook_query_expand_missing_binary(monkeypatch):
    """Returns binary_not_found when the binary isn't in the notebook."""
    monkeypatch.setenv("NEXUS_SLM_MODEL", "Qwen/Qwen2.5-Coder-1.5B-Instruct")
    ctx = _fresh_context()

    response = await notebook_query_expand(
        ctx=ctx, binary_name="missing.exe", query="x"
    )
    assert response["ok"] is False
    assert response["error_code"] == "binary_not_found"


@pytest.mark.asyncio
async def test_notebook_query_expand_slm_failure(monkeypatch):
    """Returns slm_failed with fallback when the SLM raises."""
    monkeypatch.setenv("NEXUS_SLM_MODEL", "Qwen/Qwen2.5-Coder-1.5B-Instruct")

    # Force is_available() to return True so we reach the SLM call.
    # The MCP tool imports the symbol locally as _slm_available inside
    # the function, but the underlying call is to ghidra_nexus.slm.is_available.
    monkeypatch.setattr(
        "ghidra_nexus.slm.is_available", lambda: True
    )

    # The tool imports run_query_expand locally as _slm_run_query_expand.
    # Monkeypatching the original `run_query_expand` symbol doesn't reach
    # the local alias, so we patch the SLM call directly at the source.
    def fake_run(**kwargs):
        raise RuntimeError("simulated SLM crash")

    monkeypatch.setattr(
        "ghidra_nexus.slm.run_query_expand", fake_run
    )

    from ghidra_nexus.mcp_tools import _get_notebook
    nb = await _get_notebook()
    nb.binaries.upsert(name="find.exe", sha256="a" * 64)

    ctx = _fresh_context()
    response = await notebook_query_expand(
        ctx=ctx, binary_name="find.exe", query="x"
    )
    assert response["ok"] is False
    assert response["error_code"] == "slm_failed"
    assert response["fallback_tool"] == "search_code"


@pytest.mark.asyncio
async def test_notebook_query_expand_success(monkeypatch):
    """Returns the expanded query on success."""
    monkeypatch.setenv("NEXUS_SLM_MODEL", "Qwen/Qwen2.5-Coder-1.5B-Instruct")
    monkeypatch.setattr("ghidra_nexus.slm.is_available", lambda: True)

    fake_result = ExpandedQuery(
        raw_query="connect network",
        tokens=["socket", "wsa_startup", "connect"],
        related_apis=["socket", "WSAStartup"],
        fts_query="socket OR wsa_startup OR connect",
        rationale="user asked about network",
        model="Qwen/Qwen2.5-Coder-1.5B-Instruct",
        latency_ms=250,
    )

    def fake_run(**kwargs):
        return fake_result

    monkeypatch.setattr("ghidra_nexus.slm.run_query_expand", fake_run)

    from ghidra_nexus.mcp_tools import _get_notebook
    nb = await _get_notebook()
    nb.binaries.upsert(name="find.exe", sha256="a" * 64)

    ctx = _fresh_context()
    response = await notebook_query_expand(
        ctx=ctx, binary_name="find.exe", query="connect network"
    )
    assert response["ok"] is True
    assert response["raw_query"] == "connect network"
    assert response["tokens"] == ["socket", "wsa_startup", "connect"]
    assert "WSAStartup" in response["related_apis"]
    assert response["fts_query"] == "socket OR wsa_startup OR connect"
    assert response["model"] == "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    assert response["latency_ms"] == 250


@pytest.mark.asyncio
async def test_notebook_query_expand_passes_aliases_to_slm(monkeypatch):
    """Verifies the tool pulls aliases from the notebook and forwards them to the SLM."""
    monkeypatch.setenv("NEXUS_SLM_MODEL", "Qwen/Qwen2.5-Coder-1.5B-Instruct")
    monkeypatch.setattr("ghidra_nexus.slm.is_available", lambda: True)

    captured_kwargs: dict = {}

    def fake_run(**kwargs):
        captured_kwargs.update(kwargs)
        return ExpandedQuery(
            raw_query="x",
            tokens=[],
            related_apis=[],
            fts_query="",
            rationale="",
            model="m",
            latency_ms=0,
        )

    monkeypatch.setattr("ghidra_nexus.slm.run_query_expand", fake_run)

    from ghidra_nexus.mcp_tools import _get_notebook
    nb = await _get_notebook()
    bid = nb.binaries.upsert(name="find.exe", sha256="a" * 64)
    # Add some aliases
    nb.aliases.upsert(binary_id=bid, rva="0x1000", name="init_buffer_pool", tags=None)
    nb.aliases.upsert(binary_id=bid, rva="0x2000", name="main", tags=None)

    ctx = _fresh_context()
    await notebook_query_expand(ctx=ctx, binary_name="find.exe", query="x")

    assert "init_buffer_pool" in captured_kwargs.get("known_aliases", [])
    assert "main" in captured_kwargs.get("known_aliases", [])
