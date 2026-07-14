"""Unit tests for mcp_error_handler agent-first conversion."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from ghidra_nexus.errors import ProgramAccessError, ToolErrorCode
from ghidra_nexus.mcp_tools import (
    _ToolRecoverable,
    _as_tool_error_dict,
    decompile_function,
    delete_project_binary,
    disassemble,
    mcp_error_handler,
)


class TestAsToolErrorDict:
    def test_program_access_error(self):
        exc = ProgramAccessError(
            ToolErrorCode.BINARY_NOT_FOUND, "gone", binary_name="x.exe"
        )
        body = _as_tool_error_dict(exc)
        assert body is not None
        assert body["error_code"] == "binary_not_found"
        assert body["ok"] is False

    def test_tool_recoverable(self):
        exc = _ToolRecoverable(
            ToolErrorCode.INVALID_RANGE, "bad count", binary_name="x.exe"
        )
        body = _as_tool_error_dict(exc)
        assert body is not None
        assert body["error_code"] == "invalid_range"

    def test_file_not_found(self):
        body = _as_tool_error_dict(FileNotFoundError("C:/nope"))
        assert body is not None
        assert body["error_code"] == "binary_path_unreadable"

    def test_value_error_symbol(self):
        body = _as_tool_error_dict(ValueError("Symbol 'foo' not found."))
        assert body is not None
        assert body["error_code"] == "symbol_not_found"

    def test_unknown_exception_returns_none(self):
        assert _as_tool_error_dict(RuntimeError("boom")) is None


class TestDecoratorReturnsToolError:
    @pytest.mark.asyncio
    async def test_async_handler_returns_dict_not_raise(self):
        @mcp_error_handler
        async def boom():
            raise ProgramAccessError(
                ToolErrorCode.BINARY_ANALYZING,
                "wait",
                binary_name="find.exe",
            )

        result = await boom()
        assert isinstance(result, dict)
        assert result["ok"] is False
        assert result["error_code"] == "binary_analyzing"
        assert result["fallback_tool"] == "analysis_status"

    def test_sync_handler_returns_dict_not_raise(self):
        @mcp_error_handler
        def boom():
            raise _ToolRecoverable(ToolErrorCode.INVALID_PARAMS, "nope")

        result = boom()
        assert isinstance(result, dict)
        assert result["error_code"] == "invalid_params"


class TestDisassembleInvalidRange:
    @pytest.mark.asyncio
    async def test_count_zero_returns_typed_error(self):
        ctx = Mock()
        ctx.request_context.lifespan_context = Mock()
        result = await disassemble(
            binary_name="find.exe",
            ctx=ctx,
            address="0x1000",
            count=0,
        )
        assert isinstance(result, dict)
        assert result["ok"] is False
        assert result["error_code"] == "invalid_range"


class TestDeleteMissingBinary:
    @pytest.mark.asyncio
    async def test_delete_failure_returns_typed_error(self):
        pyghidra_context = Mock()
        pyghidra_context.delete_program.return_value = False
        ctx = Mock()
        ctx.request_context.lifespan_context = pyghidra_context

        result = await delete_project_binary("missing.exe", ctx)
        assert isinstance(result, dict)
        assert result["error_code"] == "binary_not_found"


class TestDecompileMissingBinary:
    @pytest.mark.asyncio
    async def test_missing_binary_returns_tool_error(self):
        from ghidra_nexus.errors import ProgramAccessError

        pyghidra_context = Mock()
        pyghidra_context.get_program_info.side_effect = ProgramAccessError(
            ToolErrorCode.BINARY_NOT_FOUND,
            "Binary 'nope' not found",
            binary_name="nope",
        )
        ctx = Mock()
        ctx.request_context.lifespan_context = pyghidra_context

        result = await decompile_function(
            binary_name="nope",
            name_or_address="main",
            ctx=ctx,
        )
        assert isinstance(result, dict)
        assert result["ok"] is False
        assert result["error_code"] == "binary_not_found"
        assert result["fallback_tool"] == "list_project_binaries"
