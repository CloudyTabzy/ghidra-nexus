"""Structured error semantics for GhidraNexus MCP tools.

This module is the foundation of the "agent-first" rules from
``C:\\Dev\\Ghidra-MCP\\Implementations\\agent-pain-points-analysis.md`` (Patterns 1, 5, 8).

**Why this exists:** IDA Pro / Synapse MCP feedback documented that agents waste entire
investigation branches on opaque errors (e.g. ``"Decompilation failed"`` with no cause,
``"MCP error -32600: Tool X has an output schema but did not return structured content"``
with no fix). The fix here is a single, stable error schema:

.. code-block:: json

    {
      "ok": false,
      "error_code": "encrypted_bytes",
      "message": "Decompilation produced no usable output (function likely encrypted)",
      "hint": "Try disassemble(addr) instead, or skip this function.",
      "fallback_tool": "disassemble",
      "binary_name": "find.exe",
      "addr": "0x401000"
    }

Three invariants:

1. ``error_code`` is a stable string constant the agent can branch on.
2. ``hint`` is always present (one-sentence next step).
3. ``fallback_tool`` is present when an obvious next call exists.

Handlers may return either ``ToolError`` from a known-failure path (constructed via
:meth:`make_tool_error`) or via the :func:`mcp_error_handler` decorator (which converts
uncaught exceptions into typed errors).
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ToolErrorCode(str, Enum):
    """Stable, agent-branchable error codes.

    Every ``error_code`` returned by a GhidraNexus tool is one of these. New codes
    are added when a tool genuinely needs a new failure mode — don't repurpose existing
    ones, agents will branch on the strings.
    """

    # ----- Decompiler / disassembler -----
    DECOMPILE_ENCRYPTED = "encrypted_bytes"
    DECOMPILE_TOO_SMALL = "function_too_small"
    DECOMPILE_NO_LICENSE = "no_license"
    DECOMPILE_UNSUPPORTED_ISA = "unsupported_isa"
    DECOMPILE_TYPE_ERROR = "type_error"
    DECOMPILE_UNKNOWN = "decompile_failed"

    DISASSEMBLE_NO_BYTES = "no_bytes_at_address"

    # ----- Address / symbol resolution -----
    ADDRESS_NOT_FOUND = "address_not_found"
    ADDRESS_NOT_ANALYZED = "address_not_analyzed"
    ADDRESS_NOT_MAPPED = "address_not_mapped"
    SYMBOL_NOT_FOUND = "symbol_not_found"

    # ----- Binary / project lifecycle -----
    BINARY_NOT_FOUND = "binary_not_found"
    BINARY_NOT_ANALYZED = "binary_not_analyzed"
    BINARY_ANALYSIS_FAILED = "binary_analysis_failed"
    BINARY_ANALYZING = "binary_analyzing"
    BINARY_ALREADY_IMPORTED = "binary_already_imported"
    BINARY_PATH_UNREADABLE = "binary_path_unreadable"

    # ----- Validation / params -----
    INVALID_PARAMS = "invalid_params"
    INVALID_ADDRESS = "invalid_address"
    INVALID_RANGE = "invalid_range"

    # ----- Read tools -----
    STRING_NOT_FOUND = "string_not_found"

    # ----- Lifecycle -----
    SERVER_NOT_READY = "server_not_ready"
    TOOL_GUI_REQUIRED = "tool_requires_gui"

    # ----- Catch-all -----
    UNKNOWN = "unknown_error"


_FALLBACK_TOOL: dict[ToolErrorCode, str] = {
    # Decompiler
    ToolErrorCode.DECOMPILE_ENCRYPTED: "disassemble",
    ToolErrorCode.DECOMPILE_TOO_SMALL: "disassemble",
    ToolErrorCode.DECOMPILE_NO_LICENSE: "disassemble",
    ToolErrorCode.DECOMPILE_UNSUPPORTED_ISA: "disasm",
    ToolErrorCode.DECOMPILE_TYPE_ERROR: "analyze_function",
    ToolErrorCode.DISASSEMBLE_NO_BYTES: "analyze_range",
    # Address
    ToolErrorCode.ADDRESS_NOT_ANALYZED: "analyze_range",
    ToolErrorCode.ADDRESS_NOT_FOUND: "search_symbols_by_name",
    ToolErrorCode.ADDRESS_NOT_MAPPED: "list_project_binary_metadata",
    ToolErrorCode.SYMBOL_NOT_FOUND: "search_symbols_by_name",
    # Binary
    ToolErrorCode.BINARY_NOT_FOUND: "list_project_binaries",
    ToolErrorCode.BINARY_NOT_ANALYZED: "analysis_status",
    ToolErrorCode.BINARY_ANALYZING: "analysis_status",
    ToolErrorCode.BINARY_ALREADY_IMPORTED: "analysis_status",
    # Lifecycle
    ToolErrorCode.SERVER_NOT_READY: "analysis_status",
    ToolErrorCode.TOOL_GUI_REQUIRED: "list_open_programs",
}


class ToolError(BaseModel):
    """Structured error returned by every GhidraNexus MCP tool on failure.

    The Pydantic model validates the schema; FastMCP serializes it as
    ``structuredContent`` so schema-enforcing clients (OpenCode, etc.) get
    validated error shapes too.
    """

    ok: bool = Field(False, description="Always false; lets the agent discriminate with a single field check.")
    error_code: str = Field(..., description="Stable string from ToolErrorCode enum; agents branch on this.")
    message: str = Field(..., description="Human-readable description of what went wrong.")
    hint: str = Field(..., description="One-sentence suggested next action.")
    fallback_tool: str | None = Field(None, description="Recommended next tool to call, if any.")
    binary_name: str | None = Field(None, description="Set when the error is per-binary.")
    addr: str | None = Field(None, description="Set when the error is per-address.")


def make_tool_error(
    code: ToolErrorCode | str,
    message: str,
    *,
    hint: str = "",
    binary_name: str | None = None,
    addr: str | None = None,
    fallback_tool: str | None = None,
) -> dict[str, Any]:
    """Construct a tool-error response dict.

    The dict shape matches ``ToolError`` so FastMCP serializes it as structured
    content. The agent sees ``{"ok": false, "error_code": ..., ...}`` in the
    response body — never as a raised framework exception.

    Parameters
    ----------
    code
        A :class:`ToolErrorCode` member or a string constant. The latter lets
        handlers in :mod:`mcp_tools` upgrade gradually — unrecognized strings
        fall through to ``UNKNOWN``.
    message
        Human-readable description of the error. Keep under ~120 chars.
    hint
        One-sentence next step. Auto-filled from the fallback table if not given.
    binary_name, addr
        Optional context the agent can route on.
    fallback_tool
        Override the auto-filled fallback tool name.

    Returns
    -------
    dict
        A dict matching the ``ToolError`` schema (FastMCP serializes as
        ``structuredContent`` because the parent tool declares ``ToolError`` as a
        return type).
    """
    if isinstance(code, str):
        try:
            code = ToolErrorCode(code)
        except ValueError:
            code = ToolErrorCode.UNKNOWN

    if not hint:
        hint = f"Check the error_code and try again. ({code.value})"

    if fallback_tool is None:
        fallback_tool = _FALLBACK_TOOL.get(code)

    body = {
        "ok": False,
        "error_code": code.value,
        "message": message,
        "hint": hint,
        "fallback_tool": fallback_tool,
        "binary_name": binary_name,
        "addr": addr,
    }
    # Drop None values so the JSON stays compact.
    return {k: v for k, v in body.items() if v is not None}


# ---------------------------------------------------------------------------
# Decompile failure classification
# ---------------------------------------------------------------------------

_DECOMPILE_ENCRYPTED_HINTS = (
    "encrypted",
    "could not be decompiled",
    "no instruction",
    "no valid instructions",
)

_DECOMPILE_TOO_SMALL_HINTS = (
    "function size",
    "too small",
    "minimum",
    "below",
)

_DECOMPILE_NO_LICENSE_HINTS = (
    "license",
    "no decompiler",
    "decompiler is not available",
)

_UNSUPPORTED_ISA_HINTS = (
    "unsupported",
    "instruction set",
    "isa",
)


def classify_decompile_failure(error_message: str) -> ToolErrorCode:
    """Map a Ghidra ``DecompileResults.getErrorMessage()`` string to a stable code.

    Defensive: if nothing matches, returns ``DECOMPILE_UNKNOWN``. The agent then has
    one consistent field to log and search the notebook by.
    """
    if not error_message:
        return ToolErrorCode.DECOMPILE_UNKNOWN
    msg = error_message.lower()
    if any(s in msg for s in _DECOMPILE_NO_LICENSE_HINTS):
        return ToolErrorCode.DECOMPILE_NO_LICENSE
    if any(s in msg for s in _DECOMPILE_ENCRYPTED_HINTS):
        return ToolErrorCode.DECOMPILE_ENCRYPTED
    if any(s in msg for s in _DECOMPILE_TOO_SMALL_HINTS):
        return ToolErrorCode.DECOMPILE_TOO_SMALL
    if any(s in msg for s in _UNSUPPORTED_ISA_HINTS):
        return ToolErrorCode.DECOMPILE_UNSUPPORTED_ISA
    if "type" in msg and ("error" in msg or "mismatch" in msg):
        return ToolErrorCode.DECOMPILE_TYPE_ERROR
    return ToolErrorCode.DECOMPILE_UNKNOWN
