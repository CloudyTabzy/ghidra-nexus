"""Phase 5 hard gates: very_large string scan, semantic search degrade."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest

from ghidra_nexus.mcp_tools import search_code, search_strings
from ghidra_nexus.models import CodeSearchResults, SearchMode, StringSearchResults


def _mock_executor(monkeypatch, side_effect=None):
    """Replace get_executor().submit with a callable that runs fn()."""
    executor = Mock()

    async def submit(program_info, fn, *args, write=False, task_id=None, **kwargs):
        if side_effect is not None:
            return await side_effect(program_info, fn, write=write, task_id=task_id)
        return fn()

    executor.submit = submit
    monkeypatch.setattr("ghidra_nexus.mcp_tools.get_executor", lambda: executor)
    return executor


def _fresh_context(binary_name: str):
    program_info = Mock()
    program_info.name = binary_name

    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = program_info
    pyghidra_context.nexus_data_dir = None

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    return pyghidra_context, program_info, ctx


@pytest.mark.asyncio
async def test_search_strings_refuses_short_query_on_very_large(monkeypatch):
    """Very_large binaries require a query of at least 3 characters."""
    _mock_executor(monkeypatch)
    pyghidra_context, _program_info, ctx = _fresh_context("big.exe")

    # Ensure the notebook sees this binary as very_large.
    from ghidra_nexus.mcp_tools import _get_notebook

    nb = await _get_notebook(pyghidra_context)
    nb.binaries.upsert(name="big.exe", sha256="a" * 64, size_bytes=200_000_000)
    nb.conn.execute(
        "UPDATE binaries SET binary_class = ? WHERE name = ?",
        ("very_large", "big.exe"),
    )

    monkeypatch.setattr(
        "ghidra_nexus.mcp_tools._require_program",
        lambda ctx, name, require_analysis=False: (pyghidra_context, _program_info),
    )

    response = await search_strings("big.exe", ctx, "ab")
    assert response["ok"] is False
    assert response["error_code"] == "invalid_params"
    assert "very_large" in response["message"]
    assert response["fallback_tool"] == "notebook_search"


@pytest.mark.asyncio
async def test_search_strings_allows_long_query_on_very_large(monkeypatch):
    """A 3+ character query on a very_large binary reaches the executor."""
    called = asyncio.Event()

    async def submit(program_info, fn, *args, write=False, task_id=None, **kwargs):
        called.set()
        return StringSearchResults(strings=[])

    _mock_executor(monkeypatch, side_effect=submit)
    pyghidra_context, _program_info, ctx = _fresh_context("big.exe")

    from ghidra_nexus.mcp_tools import _get_notebook

    nb = await _get_notebook(pyghidra_context)
    nb.binaries.upsert(name="big.exe", sha256="a" * 64, size_bytes=200_000_000)
    nb.conn.execute(
        "UPDATE binaries SET binary_class = ? WHERE name = ?",
        ("very_large", "big.exe"),
    )

    monkeypatch.setattr(
        "ghidra_nexus.mcp_tools._require_program",
        lambda ctx, name, require_analysis=False: (pyghidra_context, _program_info),
    )

    response = await search_strings("big.exe", ctx, "abc")
    assert called.is_set()
    assert isinstance(response, StringSearchResults)


@pytest.mark.asyncio
async def test_search_code_semantic_unavailable_returns_typed_error(monkeypatch):
    """search_mode='semantic' with vec unavailable returns SEMANTIC_BACKEND_UNAVAILABLE."""
    _mock_executor(monkeypatch)
    pyghidra_context, _program_info, ctx = _fresh_context("sample.exe")

    from ghidra_nexus.mcp_tools import _get_notebook

    nb = await _get_notebook(pyghidra_context)
    nb.binaries.upsert(name="sample.exe", sha256="a" * 64)
    # Force vec unavailable without breaking other notebook internals.
    from ghidra_nexus.notebook.vec import VecStatus
    nb._vec_status = VecStatus(available=False, error="disabled for test")

    monkeypatch.setattr(
        "ghidra_nexus.mcp_tools._require_program",
        lambda ctx, name, require_analysis=False: (pyghidra_context, _program_info),
    )

    response = await search_code("sample.exe", "main", ctx, search_mode="semantic")
    assert response["ok"] is False
    assert response["error_code"] == "semantic_backend_unavailable"
    assert response["fallback_tool"] == "notebook_embed_status"


@pytest.mark.asyncio
async def test_search_code_semantic_index_incomplete_falls_back_to_fts(monkeypatch):
    """search_mode='semantic' when index incomplete returns FTS results with a note."""
    _mock_executor(monkeypatch)
    pyghidra_context, _program_info, ctx = _fresh_context("sample.exe")

    from ghidra_nexus.mcp_tools import _get_notebook

    nb = await _get_notebook(pyghidra_context)
    nb.binaries.upsert(name="sample.exe", sha256="a" * 64)
    nb.conn.execute(
        "UPDATE binaries SET vec_index_complete = 0 WHERE name = ?",
        ("sample.exe",),
    )
    # vec is "available" from the extension POV but index isn't complete.
    from ghidra_nexus.notebook.vec import VecStatus
    nb._vec_status = VecStatus(available=True)

    # Seed an artifact view + FTS row so hybrid_search has something to return.
    bid = nb.binaries.get("sample.exe")["id"]
    nb.views.upsert(
        binary_id=bid,
        rva="0x1000",
        kind="decompile",
        summary="main function entry point",
        key_entities='[]',
    )
    nb.conn.execute(
        "INSERT INTO fts (kind, binary_id, rva, name, body) VALUES (?, ?, ?, ?, ?)",
        ("decompile", bid, "0x1000", "main", "main function entry point"),
    )

    monkeypatch.setattr(
        "ghidra_nexus.mcp_tools._require_program",
        lambda ctx, name, require_analysis=False: (pyghidra_context, _program_info),
    )

    response = await search_code("sample.exe", "entry", ctx, search_mode="semantic")
    assert isinstance(response, CodeSearchResults)
    assert response.search_mode == SearchMode.SEMANTIC
    assert response.backend == "fts_only"
    assert response.vec_index_complete is False
    assert any("still building" in note for note in response.reliability_notes)
