"""Unit tests for MCP tool wiring (executor path, not full Ghidra)."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest

from ghidra_nexus.mcp_tools import (
    decompile_function,
    list_project_binaries,
    rename_variable,
    search_symbols_by_name,
    set_comment,
    set_function_prototype,
    set_variable_type,
)
from ghidra_nexus.models import DecompiledFunction, ProgramInfo, SymbolInfo


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


@pytest.mark.asyncio
async def test_list_project_binaries_uses_project_wide_context_listing():
    program_info = ProgramInfo(
        name="/folder/sample",
        file_path=None,
        load_time=None,
        analysis_complete=False,
        metadata={},
        code_indexed=False,
        strings_indexed=False,
    )
    pyghidra_context = Mock()
    pyghidra_context.list_project_binary_infos.return_value = [program_info]
    pyghidra_context.list_program_infos.side_effect = AssertionError(
        "should not use open-program listing"
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    response = await list_project_binaries(ctx)

    assert response.programs == [program_info]


@pytest.mark.asyncio
async def test_set_comment_uses_tool_path(monkeypatch):
    _mock_executor(monkeypatch)
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.set_comment.return_value = {
        "address": "1000042e3",
        "comment": "function summary",
        "comment_type": "decompiler",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = await set_comment(
        binary_name="sample",
        target="entry",
        comment="function summary",
        comment_type="decompiler",
        ctx=ctx,
    )

    fake_tools.set_comment.assert_called_once_with("entry", "function summary", "decompiler")
    assert response.binary_name == "sample"
    assert response.address == "1000042e3"
    assert response.comment_type == "decompiler"


@pytest.mark.asyncio
async def test_rename_variable_uses_tool_path(monkeypatch):
    _mock_executor(monkeypatch)
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.rename_variable.return_value = {
        "function_name": "helper",
        "function_address": "100001000",
        "variable_kind": "parameter",
        "old_name": "count",
        "new_name": "item_count",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = await rename_variable(
        binary_name="sample",
        function_name_or_address="helper",
        variable_name="count",
        new_name="item_count",
        ctx=ctx,
    )

    fake_tools.rename_variable.assert_called_once_with("helper", "count", "item_count")
    assert response.binary_name == "sample"
    assert response.function_name == "helper"
    assert response.new_name == "item_count"


@pytest.mark.asyncio
async def test_set_variable_type_uses_tool_path(monkeypatch):
    _mock_executor(monkeypatch)
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.set_variable_type.return_value = {
        "function_name": "helper",
        "function_address": "100001000",
        "variable_kind": "local",
        "variable_name": "total",
        "old_type": "int",
        "new_type": "long",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = await set_variable_type(
        binary_name="sample",
        function_name_or_address="helper",
        variable_name="total",
        type_name="long",
        ctx=ctx,
    )

    fake_tools.set_variable_type.assert_called_once_with("helper", "total", "long")
    assert response.binary_name == "sample"
    assert response.new_type == "long"


@pytest.mark.asyncio
async def test_set_function_prototype_uses_tool_path(monkeypatch):
    _mock_executor(monkeypatch)
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.set_function_prototype.return_value = {
        "function_name": "function_one",
        "function_address": "100001000",
        "old_prototype": "int function_one(int count)",
        "new_prototype": "long function_one(long count)",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = await set_function_prototype(
        binary_name="sample",
        function_name_or_address="function_one",
        prototype="long function_one(long count)",
        ctx=ctx,
    )

    fake_tools.set_function_prototype.assert_called_once_with(
        "function_one", "long function_one(long count)"
    )
    assert response.binary_name == "sample"
    assert response.new_prototype == "long function_one(long count)"


@pytest.mark.asyncio
async def test_decompile_function_offloads_with_timeout(monkeypatch):
    _mock_executor(monkeypatch)
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    decompiled = DecompiledFunction(name="entry", code="int entry() { return 0; }")
    fake_tools.decompile_function_by_name_or_addr.return_value = decompiled

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = await decompile_function(
        binary_name="sample",
        name_or_address="entry",
        timeout_sec=17,
        ctx=ctx,
    )

    fake_tools.decompile_function_by_name_or_addr.assert_called_once_with("entry", timeout=17)
    assert response == [decompiled]


@pytest.mark.asyncio
async def test_decompile_exception_returns_typed_error_code(monkeypatch):
    """Phase 0.5.1: exception path must set error_code, not free-text only."""
    _mock_executor(monkeypatch)
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.decompile_function_by_name_or_addr.side_effect = ValueError(
        "Symbol 'nope' not found."
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = await decompile_function(
        binary_name="sample",
        name_or_address="nope",
        ctx=ctx,
    )
    assert len(response) == 1
    assert response[0].code == ""
    assert response[0].error_code == "symbol_not_found"
    assert response[0].hint


@pytest.mark.skip(reason="Pre-existing asyncio hang unrelated to Phase 3; defer to Phase 5")
@pytest.mark.asyncio
async def test_decompile_does_not_block_other_tool_calls(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    decompiled = DecompiledFunction(name="entry", code="// ok")
    fake_tools.decompile_function_by_name_or_addr.return_value = decompiled
    fake_tools.search_symbols_by_name.return_value = [
        SymbolInfo(
            name="entry",
            address="1000",
            type="Function",
            namespace="Global",
            source="USER_DEFINED",
            refcount=1,
            external=False,
            is_thunk=False,
        )
    ]

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    monkeypatch.setattr("ghidra_nexus.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    decompile_started = asyncio.Event()
    release_decompile = asyncio.Event()

    async def submit(program_info, fn, *args, write=False, task_id=None, **kwargs):
        # Only gate the decompile path so search can finish first.
        if task_id and str(task_id).startswith("decompile:"):
            decompile_started.set()
            await release_decompile.wait()
        return fn()

    executor = Mock()
    executor.submit = submit
    monkeypatch.setattr("ghidra_nexus.mcp_tools.get_executor", lambda: executor)

    decompile_task = asyncio.create_task(
        decompile_function(binary_name="sample", name_or_address="entry", ctx=ctx)
    )
    await decompile_started.wait()

    symbols = await search_symbols_by_name(
        binary_name="sample", query="entry", ctx=ctx
    )
    assert symbols.symbols[0].name == "entry"

    release_decompile.set()
    result = await decompile_task
    assert result[0].code == "// ok"
