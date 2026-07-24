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
3. ``fallback_tool`` is present when an obvious next call exists — and **must name a
   real registered MCP tool** (never a ghost like ``analyze_range``).

Handlers may return either ``ToolError`` from a known-failure path (constructed via
:func:`make_tool_error`) or via the :func:`mcp_error_handler` decorator (which converts
uncaught recoverable exceptions into typed errors).
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ToolErrorCode(str, Enum):
    """Stable, agent-branchable error codes.

    Every ``error_code`` returned by a GhidraNexus tool is one of these. New codes
    are added when a tool genuinely needs a new failure mode — don't repurpose existing
    ones; agents will branch on the strings.
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
    SYMBOL_AMBIGUOUS = "symbol_ambiguous"

    # ----- Binary / project lifecycle -----
    BINARY_NOT_FOUND = "binary_not_found"
    BINARY_NOT_ANALYZED = "binary_not_analyzed"
    BINARY_ANALYSIS_FAILED = "binary_analysis_failed"
    BINARY_ANALYZING = "binary_analyzing"
    BINARY_ALREADY_IMPORTED = "binary_already_imported"
    BINARY_PATH_UNREADABLE = "binary_path_unreadable"
    BINARY_DELETED = "binary_deleted"

    # ----- Validation / params -----
    INVALID_PARAMS = "invalid_params"
    INVALID_ADDRESS = "invalid_address"
    INVALID_RANGE = "invalid_range"

    # ----- Read tools -----
    STRING_NOT_FOUND = "string_not_found"

    # ----- Lifecycle -----
    SERVER_NOT_READY = "server_not_ready"
    TOOL_GUI_REQUIRED = "tool_requires_gui"

    # ----- Notebook / knowledge plane -----
    SEMANTIC_BACKEND_UNAVAILABLE = "semantic_backend_unavailable"
    NOTEBOOK_NOT_READY = "notebook_not_ready"

    # SLM (Phase 6)
    SLM_DISABLED = "slm_disabled"
    SLM_FAILED = "slm_failed"

    # ----- Catch-all -----
    UNKNOWN = "unknown_error"


# Tools that actually exist in server.py / register_common_tools.
# fallback_tool values MUST be a member of this set (or None).
REGISTERED_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "decompile_function",
        "search_symbols_by_name",
        "search_code",
        "list_project_binaries",
        "list_project_binary_metadata",
        "rename_function",
        "rename_variable",
        "set_variable_type",
        "set_function_prototype",
        "set_comment",
        "delete_project_binary",
        "list_exports",
        "list_imports",
        "list_xrefs",
        "search_strings",
        "read_bytes",
        "disassemble",
        "disassemble_call_site",
        "verify_port",
        "gen_callgraph",
        "analysis_status",
        "import_binary",
        "survey_binary",
        "survey_binary_fast",
        "survey_binary_full",
        "section_health",
        "save",
        "list_open_programs",
        "open_program_in_gui",
        "set_current_program",
        "goto",
        "get_gui_context",
        "wake_ghidra",
        "ghidra_status",
        "notebook_summary",
        "notebook_search",
        "notebook_breadcrumbs",
        "notebook_alias",
        "notebook_hypothesis",
        "notebook_embed_status",
        "notebook_rebuild_embeddings",
        "notebook_archive_breadcrumbs",
        "notebook_vacuum",
        "notebook_query_expand",
    }
)


_FALLBACK_TOOL: dict[ToolErrorCode, str] = {
    # Decompiler — always fall back to disassemble (real tool)
    ToolErrorCode.DECOMPILE_ENCRYPTED: "disassemble",
    ToolErrorCode.DECOMPILE_TOO_SMALL: "disassemble",
    ToolErrorCode.DECOMPILE_NO_LICENSE: "disassemble",
    ToolErrorCode.DECOMPILE_UNSUPPORTED_ISA: "disassemble",
    ToolErrorCode.DECOMPILE_TYPE_ERROR: "set_function_prototype",
    ToolErrorCode.DECOMPILE_UNKNOWN: "disassemble",
    ToolErrorCode.DISASSEMBLE_NO_BYTES: "section_health",
    # Address / symbol
    ToolErrorCode.ADDRESS_NOT_ANALYZED: "disassemble",
    ToolErrorCode.ADDRESS_NOT_FOUND: "search_symbols_by_name",
    ToolErrorCode.ADDRESS_NOT_MAPPED: "list_project_binary_metadata",
    ToolErrorCode.SYMBOL_NOT_FOUND: "search_symbols_by_name",
    ToolErrorCode.SYMBOL_AMBIGUOUS: "search_symbols_by_name",
    # Binary lifecycle
    ToolErrorCode.BINARY_NOT_FOUND: "list_project_binaries",
    ToolErrorCode.BINARY_NOT_ANALYZED: "analysis_status",
    ToolErrorCode.BINARY_ANALYSIS_FAILED: "analysis_status",
    ToolErrorCode.BINARY_ANALYZING: "analysis_status",
    ToolErrorCode.BINARY_ALREADY_IMPORTED: "analysis_status",
    ToolErrorCode.BINARY_PATH_UNREADABLE: "import_binary",
    ToolErrorCode.BINARY_DELETED: "list_project_binaries",
    # Validation
    ToolErrorCode.INVALID_PARAMS: "analysis_status",
    ToolErrorCode.INVALID_ADDRESS: "search_symbols_by_name",
    ToolErrorCode.STRING_NOT_FOUND: "search_strings",
    # Lifecycle
    ToolErrorCode.SERVER_NOT_READY: "analysis_status",
    ToolErrorCode.TOOL_GUI_REQUIRED: "list_open_programs",
    # Notebook
    ToolErrorCode.SEMANTIC_BACKEND_UNAVAILABLE: "notebook_embed_status",
    ToolErrorCode.NOTEBOOK_NOT_READY: "notebook_summary",
    ToolErrorCode.SLM_DISABLED: "search_code",
    ToolErrorCode.SLM_FAILED: "search_code",
}


_DEFAULT_HINTS: dict[ToolErrorCode, str] = {
    ToolErrorCode.DECOMPILE_ENCRYPTED: (
        "Call disassemble(addr) for raw instructions, or section_health to confirm encryption."
    ),
    ToolErrorCode.DECOMPILE_TOO_SMALL: (
        "Function is too small for decompilation; call disassemble(addr) or skip as a stub."
    ),
    ToolErrorCode.DECOMPILE_NO_LICENSE: (
        "Decompiler unavailable; use disassemble(addr) for assembly instead."
    ),
    ToolErrorCode.DECOMPILE_UNSUPPORTED_ISA: (
        "ISA not supported by decompiler; use disassemble(addr)."
    ),
    ToolErrorCode.DECOMPILE_TYPE_ERROR: (
        "Try set_function_prototype with a simpler signature, then re-decompile."
    ),
    ToolErrorCode.DECOMPILE_UNKNOWN: (
        "Call disassemble(addr) to inspect raw instructions, or skip this function."
    ),
    ToolErrorCode.DISASSEMBLE_NO_BYTES: (
        "No bytes at that address; call section_health to see mapped ranges."
    ),
    ToolErrorCode.ADDRESS_NOT_ANALYZED: (
        "Address may be outside analyzed ranges; try disassemble(addr) or section_health."
    ),
    ToolErrorCode.ADDRESS_NOT_FOUND: (
        "Call search_symbols_by_name with a partial name, or list_exports."
    ),
    ToolErrorCode.ADDRESS_NOT_MAPPED: (
        "Call list_project_binary_metadata to see image base and memory map."
    ),
    ToolErrorCode.SYMBOL_NOT_FOUND: (
        "Call search_symbols_by_name with a partial query, or list_exports."
    ),
    ToolErrorCode.SYMBOL_AMBIGUOUS: (
        "Multiple matches; call search_symbols_by_name and pick an exact address."
    ),
    ToolErrorCode.BINARY_NOT_FOUND: (
        "Call list_project_binaries to see loaded names, or import_binary first."
    ),
    ToolErrorCode.BINARY_NOT_ANALYZED: (
        "Poll analysis_status until analysis_complete is true."
    ),
    ToolErrorCode.BINARY_ANALYSIS_FAILED: (
        "Call analysis_status for path_warnings; re-import or move project path."
    ),
    ToolErrorCode.BINARY_ANALYZING: (
        "Poll analysis_status; use survey_binary_fast / section_health while waiting."
    ),
    ToolErrorCode.BINARY_ALREADY_IMPORTED: (
        "Binary is already in the project; call analysis_status or survey_binary_full."
    ),
    ToolErrorCode.BINARY_PATH_UNREADABLE: (
        "Check the path exists and is readable; pass an absolute path to import_binary."
    ),
    ToolErrorCode.BINARY_DELETED: (
        "Binary was deleted; call list_project_binaries or re-import."
    ),
    ToolErrorCode.INVALID_PARAMS: (
        "Check tool arguments against the schema; call analysis_status for project state."
    ),
    ToolErrorCode.INVALID_ADDRESS: (
        "Pass a hex address or exact symbol name; try search_symbols_by_name."
    ),
    ToolErrorCode.INVALID_RANGE: (
        "Adjust count/size to a positive value within tool limits."
    ),
    ToolErrorCode.STRING_NOT_FOUND: (
        "Broaden the query or call search_strings with a simpler pattern."
    ),
    ToolErrorCode.SERVER_NOT_READY: (
        "Wait for server startup, or call wake_ghidra / analysis_status."
    ),
    ToolErrorCode.TOOL_GUI_REQUIRED: (
        "Restart with --gui, or use headless tools only."
    ),
    ToolErrorCode.UNKNOWN: (
        "Check the error_code and message; call analysis_status for project state."
    ),
}


class ToolError(BaseModel):
    """Structured error returned by every GhidraNexus MCP tool on failure.

    The Pydantic model validates the schema; FastMCP serializes it as
    ``structuredContent`` so schema-enforcing clients get validated error shapes.
    """

    ok: bool = Field(
        False,
        description="Always false; agents discriminate with a single field check.",
    )
    error_code: str = Field(
        ...,
        description="Stable string from ToolErrorCode; agents branch on this.",
    )
    message: str = Field(..., description="Human-readable description of what went wrong.")
    hint: str = Field(..., description="One-sentence suggested next action.")
    fallback_tool: str | None = Field(
        None, description="Recommended next tool to call (always a real registered name)."
    )
    binary_name: str | None = Field(None, description="Set when the error is per-binary.")
    addr: str | None = Field(None, description="Set when the error is per-address.")


class ProgramAccessError(Exception):
    """Raised by context layer when a program cannot be used for a tool call.

    The MCP decorator converts this into a structured :class:`ToolError` response
    body (never a framework re-raise). Carries a stable :class:`ToolErrorCode`.
    """

    def __init__(
        self,
        code: ToolErrorCode,
        message: str,
        *,
        binary_name: str | None = None,
        addr: str | None = None,
        hint: str = "",
        fallback_tool: str | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.binary_name = binary_name
        self.addr = addr
        self.hint = hint
        self.fallback_tool = fallback_tool

    def to_tool_error_dict(self) -> dict[str, Any]:
        return make_tool_error(
            self.code,
            self.message,
            hint=self.hint,
            binary_name=self.binary_name,
            addr=self.addr,
            fallback_tool=self.fallback_tool,
        )


def make_tool_error(
    code: ToolErrorCode | str,
    message: str,
    *,
    hint: str = "",
    binary_name: str | None = None,
    addr: str | None = None,
    fallback_tool: str | None = None,
) -> dict[str, Any]:
    """Construct a tool-error response dict matching :class:`ToolError`.

    Parameters
    ----------
    code
        A :class:`ToolErrorCode` member or a string constant. Unrecognized
        strings fall through to ``UNKNOWN``.
    message
        Human-readable description. Keep under ~120 chars when possible.
    hint
        One-sentence next step. Auto-filled from the default-hint table if empty.
    binary_name, addr
        Optional context the agent can route on.
    fallback_tool
        Override the auto-filled fallback. Must be a registered tool name when set.
    """
    if isinstance(code, str):
        try:
            code = ToolErrorCode(code)
        except ValueError:
            code = ToolErrorCode.UNKNOWN

    if not hint:
        hint = _DEFAULT_HINTS.get(
            code, f"Check the error_code and try again. ({code.value})"
        )

    if fallback_tool is None:
        fallback_tool = _FALLBACK_TOOL.get(code)
    # Never point the agent at a ghost tool.
    if fallback_tool is not None and fallback_tool not in REGISTERED_TOOL_NAMES:
        fallback_tool = None

    body: dict[str, Any] = {
        "ok": False,
        "error_code": code.value,
        "message": message,
        "hint": hint,
        "fallback_tool": fallback_tool,
        "binary_name": binary_name,
        "addr": addr,
    }
    return {k: v for k, v in body.items() if v is not None}


# ---------------------------------------------------------------------------
# Decompile failure classification
# ---------------------------------------------------------------------------

_DECOMPILE_ENCRYPTED_HINTS = (
    "encrypted",
    "could not be decompiled",
    "no instruction",
    "no valid instructions",
    "low-level error",
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

    Defensive: if nothing matches, returns ``DECOMPILE_UNKNOWN``.
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


def classify_lookup_failure(
    error_message: str,
    *,
    binary_name: str | None = None,
) -> ToolErrorCode:
    """Map free-text symbol/function lookup failures to a stable code."""
    msg = (error_message or "").lower()
    if "ambiguous" in msg:
        return ToolErrorCode.SYMBOL_AMBIGUOUS
    if "not found" in msg or "no such" in msg:
        if "binary" in msg or "program" in msg:
            return ToolErrorCode.BINARY_NOT_FOUND
        return ToolErrorCode.SYMBOL_NOT_FOUND
    if "analysis incomplete" in msg or "still in progress" in msg:
        return ToolErrorCode.BINARY_ANALYZING
    if "deleted" in msg:
        return ToolErrorCode.BINARY_DELETED
    if "not analyzed" in msg:
        return ToolErrorCode.BINARY_NOT_ANALYZED
    if binary_name and "binary" in msg:
        return ToolErrorCode.BINARY_NOT_FOUND
    return ToolErrorCode.UNKNOWN


def decompile_failure_result(
    name: str,
    error_message: str,
    *,
    binary_name: str | None = None,
    addr: str | None = None,
) -> dict[str, Any]:
    """Build fields for a failed :class:`~ghidra_nexus.models.DecompiledFunction`.

    Returns kwargs suitable for ``DecompiledFunction(...)`` so code is empty,
    ``error`` holds the message, and ``error_code`` / ``hint`` are typed.
    """
    code_enum = classify_decompile_failure(error_message)
    # Also try lookup-style failures (symbol not found raised as ValueError).
    if code_enum is ToolErrorCode.DECOMPILE_UNKNOWN:
        lookup = classify_lookup_failure(error_message, binary_name=binary_name)
        if lookup is not ToolErrorCode.UNKNOWN:
            code_enum = lookup
    err = make_tool_error(
        code_enum,
        error_message or "Decompilation failed",
        binary_name=binary_name,
        addr=addr,
    )
    return {
        "name": name,
        "code": "",
        "signature": None,
        "error": error_message or "Decompilation failed",
        "decompiler_status": "decompiler_error",
        "error_code": err["error_code"],
        "hint": err.get("hint"),
    }
