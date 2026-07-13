"""Unit tests for ghidra_nexus.errors — the structured ToolError + helper.

These tests focus on schema correctness and the ``classify_decompile_failure``
mapping heuristic. Integration tests against real Ghidra live in
``tests/integration``.
"""

from __future__ import annotations

import pytest

from ghidra_nexus.errors import (
    ToolErrorCode,
    classify_decompile_failure,
    make_tool_error,
)


class TestMakeToolError:
    def test_minimal_call_produces_required_fields(self):
        body = make_tool_error(ToolErrorCode.BINARY_NOT_FOUND, "no such binary")
        assert body["ok"] is False
        assert body["error_code"] == "binary_not_found"
        assert body["message"] == "no such binary"
        assert body["hint"]  # auto-populated
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

    def test_no_fallback_for_truly_lifecycle_codes(self):
        # BINARY_ALREADY_IMPORTED is purely a status notification — there's no
        # obvious next tool; the agent should re-poll analysis_status itself.
        body = make_tool_error(ToolErrorCode.BINARY_ALREADY_IMPORTED, "already there")
        assert body["fallback_tool"] == "analysis_status"
        body = make_tool_error(ToolErrorCode.INVALID_RANGE, "out of range")
        # No fallback registered → stripped from the response entirely.
        assert "fallback_tool" not in body

    def test_explicit_fallback_overrides_table(self):
        body = make_tool_error(
            ToolErrorCode.BINARY_NOT_FOUND, "x", fallback_tool="import_binary"
        )
        assert body["fallback_tool"] == "import_binary"

    def test_hint_overrides_default(self):
        body = make_tool_error(
            ToolErrorCode.DECOMPILE_ENCRYPTED,
            "x",
            hint="call disassemble instead",
        )
        assert body["hint"] == "call disassemble instead"


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


class TestFallbackTableCoverage:
    """Every ToolErrorCode that has a natural fallback must be in the table.

    Tests guard against accidentally removing rows; the day we add a new code
    without a fallback, this test name will be the first hit.
    """

    EXPECTED_FALLBACKS = {
        ToolErrorCode.DECOMPILE_ENCRYPTED,
        ToolErrorCode.DECOMPILE_TOO_SMALL,
        ToolErrorCode.DECOMPILE_NO_LICENSE,
        ToolErrorCode.DECOMPILE_UNSUPPORTED_ISA,
        ToolErrorCode.DECOMPILE_TYPE_ERROR,
        ToolErrorCode.DISASSEMBLE_NO_BYTES,
        ToolErrorCode.ADDRESS_NOT_ANALYZED,
        ToolErrorCode.ADDRESS_NOT_FOUND,
        ToolErrorCode.ADDRESS_NOT_MAPPED,
        ToolErrorCode.SYMBOL_NOT_FOUND,
        ToolErrorCode.BINARY_NOT_FOUND,
        ToolErrorCode.BINARY_NOT_ANALYZED,
        ToolErrorCode.BINARY_ANALYZING,
        ToolErrorCode.BINARY_ALREADY_IMPORTED,
        ToolErrorCode.SERVER_NOT_READY,
        ToolErrorCode.TOOL_GUI_REQUIRED,
    }

    def test_fallbacks_present(self):
        from ghidra_nexus.errors import _FALLBACK_TOOL

        missing = self.EXPECTED_FALLBACKS - set(_FALLBACK_TOOL.keys())
        assert not missing, f"Missing fallback rows for: {missing}"
