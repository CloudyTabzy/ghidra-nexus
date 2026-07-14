"""Unit tests for ghidra_nexus.errors — structured ToolError + helpers.

These tests focus on schema correctness, fallback integrity (no ghost tools),
and classification heuristics. Integration tests live under tests/integration.
"""

from __future__ import annotations

import pytest

from ghidra_nexus.errors import (
    REGISTERED_TOOL_NAMES,
    ProgramAccessError,
    ToolError,
    ToolErrorCode,
    _FALLBACK_TOOL,
    classify_decompile_failure,
    classify_lookup_failure,
    decompile_failure_result,
    make_tool_error,
)


class TestMakeToolError:
    def test_minimal_call_produces_required_fields(self):
        body = make_tool_error(ToolErrorCode.BINARY_NOT_FOUND, "no such binary")
        assert body["ok"] is False
        assert body["error_code"] == "binary_not_found"
        assert body["message"] == "no such binary"
        assert body["hint"]
        assert body["fallback_tool"] == "list_project_binaries"

    def test_string_code_is_normalized(self):
        body = make_tool_error("encrypted_bytes", "boom")
        assert body["error_code"] == "encrypted_bytes"

    def test_unknown_string_code_collapses_to_unknown(self):
        body = make_tool_error("totally_made_up_code", "boom")
        assert body["error_code"] == "unknown_error"

    def test_optional_fields_strip_none(self):
        body = make_tool_error(
            ToolErrorCode.ADDRESS_NOT_FOUND,
            "no such addr",
            binary_name="find.exe",
            addr="0x401000",
        )
        assert body["binary_name"] == "find.exe"
        assert body["addr"] == "0x401000"

    def test_fallback_for_lifecycle_codes(self):
        body = make_tool_error(ToolErrorCode.BINARY_ALREADY_IMPORTED, "already there")
        assert body["fallback_tool"] == "analysis_status"

    def test_invalid_range_has_no_fallback_or_valid(self):
        body = make_tool_error(ToolErrorCode.INVALID_RANGE, "out of range")
        # Either no fallback, or a registered tool name.
        fb = body.get("fallback_tool")
        assert fb is None or fb in REGISTERED_TOOL_NAMES

    def test_explicit_fallback_overrides_table(self):
        body = make_tool_error(
            ToolErrorCode.BINARY_NOT_FOUND, "x", fallback_tool="import_binary"
        )
        assert body["fallback_tool"] == "import_binary"

    def test_ghost_fallback_is_stripped(self):
        body = make_tool_error(
            ToolErrorCode.BINARY_NOT_FOUND,
            "x",
            fallback_tool="analyze_range",  # does not exist
        )
        assert "fallback_tool" not in body

    def test_hint_overrides_default(self):
        body = make_tool_error(
            ToolErrorCode.DECOMPILE_ENCRYPTED,
            "x",
            hint="call disassemble instead",
        )
        assert body["hint"] == "call disassemble instead"

    def test_pydantic_round_trip(self):
        body = make_tool_error(ToolErrorCode.SYMBOL_NOT_FOUND, "missing")
        err = ToolError(**body)
        assert err.ok is False
        assert err.error_code == "symbol_not_found"


class TestFallbackTableIntegrity:
    """Every fallback_tool must name a real registered MCP tool."""

    def test_all_fallbacks_are_registered(self):
        ghosts = {
            code: tool
            for code, tool in _FALLBACK_TOOL.items()
            if tool not in REGISTERED_TOOL_NAMES
        }
        assert not ghosts, f"Ghost fallback tools: {ghosts}"

    def test_no_analyze_range_or_disasm_alias(self):
        forbidden = {"analyze_range", "analyze_function", "disasm"}
        used = set(_FALLBACK_TOOL.values())
        assert not (used & forbidden), f"Forbidden ghost names still in table: {used & forbidden}"

    def test_expected_critical_fallbacks(self):
        assert _FALLBACK_TOOL[ToolErrorCode.DECOMPILE_ENCRYPTED] == "disassemble"
        assert _FALLBACK_TOOL[ToolErrorCode.DECOMPILE_UNSUPPORTED_ISA] == "disassemble"
        assert _FALLBACK_TOOL[ToolErrorCode.ADDRESS_NOT_ANALYZED] == "disassemble"
        assert _FALLBACK_TOOL[ToolErrorCode.BINARY_ANALYZING] == "analysis_status"
        assert _FALLBACK_TOOL[ToolErrorCode.DECOMPILE_TYPE_ERROR] == "set_function_prototype"


class TestClassifyDecompileFailure:
    @pytest.mark.parametrize(
        "error_message, expected",
        [
            ("No decompiler license available", ToolErrorCode.DECOMPILE_NO_LICENSE),
            ("Function size is too small for analysis", ToolErrorCode.DECOMPILE_TOO_SMALL),
            ("Decompiler could not be evaluated: encrypted", ToolErrorCode.DECOMPILE_ENCRYPTED),
            ("no valid instructions at address", ToolErrorCode.DECOMPILE_ENCRYPTED),
            ("Unsupported ISA: AVR", ToolErrorCode.DECOMPILE_UNSUPPORTED_ISA),
            ("Type mismatch: cannot deduce pointer type", ToolErrorCode.DECOMPILE_TYPE_ERROR),
            ("", ToolErrorCode.DECOMPILE_UNKNOWN),
            ("some other random Ghidra error", ToolErrorCode.DECOMPILE_UNKNOWN),
        ],
    )
    def test_maps_known_strings_to_codes(self, error_message, expected):
        assert classify_decompile_failure(error_message) is expected

    def test_case_insensitive(self):
        assert (
            classify_decompile_failure("NO DECOMPILER LICENSE")
            is ToolErrorCode.DECOMPILE_NO_LICENSE
        )


class TestClassifyLookupFailure:
    def test_symbol_not_found(self):
        assert (
            classify_lookup_failure("Symbol 'foo' not found.")
            is ToolErrorCode.SYMBOL_NOT_FOUND
        )

    def test_ambiguous(self):
        assert (
            classify_lookup_failure("Ambiguous match for 'main'")
            is ToolErrorCode.SYMBOL_AMBIGUOUS
        )

    def test_binary_not_found(self):
        assert (
            classify_lookup_failure("Binary 'x' not found. Available: []")
            is ToolErrorCode.BINARY_NOT_FOUND
        )

    def test_analyzing(self):
        assert (
            classify_lookup_failure("Analysis incomplete for binary 'x'")
            is ToolErrorCode.BINARY_ANALYZING
        )


class TestDecompileFailureResult:
    def test_empty_code_on_failure(self):
        fields = decompile_failure_result(
            "main", "no valid instructions", binary_name="find.exe", addr="0x401000"
        )
        assert fields["code"] == ""
        assert fields["error_code"] == "encrypted_bytes"
        assert fields["hint"]
        assert fields["error"]

    def test_lookup_style_exception_maps_to_symbol(self):
        fields = decompile_failure_result(
            "nope", "Symbol 'nope' not found.", binary_name="find.exe"
        )
        assert fields["error_code"] == "symbol_not_found"


class TestProgramAccessError:
    def test_to_tool_error_dict(self):
        exc = ProgramAccessError(
            ToolErrorCode.BINARY_ANALYZING,
            "still going",
            binary_name="find.exe",
        )
        body = exc.to_tool_error_dict()
        assert body["ok"] is False
        assert body["error_code"] == "binary_analyzing"
        assert body["fallback_tool"] == "analysis_status"
        assert body["binary_name"] == "find.exe"
