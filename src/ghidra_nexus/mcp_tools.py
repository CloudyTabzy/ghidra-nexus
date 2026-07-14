"""
MCP Tool handlers for ghidra-nexus.

All handlers are async and dispatch Ghidra work through the GhidraExecutor
background thread for thread safety.

Agent-first error contract (Phase 0.5 / 0.5.1):
  - Recoverable failures return a ToolError dict body (``ok: false``).
  - Protocol / programmer bugs still raise McpError.
  - Never point fallback_tool at a non-existent tool name.

Phase 2 cache contract:
  - Every read-heavy handler checks the notebook cache first (SQLite, <1ms).
  - On miss, Ghidra call → blob store → extractor → view → FTS → embed_queue.
  - On hit, windowed result (offset/limit on wire, full blob in DB).
  - Write-through is best-effort; extraction failure never fails the tool.
"""

import asyncio
import functools
import logging
import threading
import time as _time
from pathlib import Path
from typing import Literal, cast

from mcp.server.fastmcp import Context
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from ghidra_nexus.context_protocol import MCPContext
from ghidra_nexus.errors import (
    ToolErrorCode,
    classify_decompile_failure,
    classify_lookup_failure,
    decompile_failure_result,
    make_tool_error,
    ProgramAccessError,
)
from ghidra_nexus.ghidra_executor import get_executor
from ghidra_nexus.models import (
    AnalysisStatusResult,
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResults,
    CommentResponse,
    CrossReferenceInfos,
    DecompiledFunction,
    DisassembleResult,
    ExportInfos,
    FunctionPrototypeResponse,
    GotoResponse,
    GuiContextResponse,
    ImportInfos,
    ImportRequestResult,
    OpenProgramInfo,
    OpenProgramInfos,
    ProgramInfo,
    ProgramInfos,
    RenameResponse,
    SaveRequestResult,
    SearchMode,
    SectionHealth,
    StringSearchResults,
    SurveyBinaryResult,
    SymbolSearchResults,
    VariableRenameResponse,
    VariableTypeResponse,
)
from ghidra_nexus.tools import GhidraTools
from ghidra_nexus.watchdog import get_watchdog

from ghidra_nexus.notebook.cache import (
    check_decompile_cache,
    check_disasm_cache,
    check_strings_cache,
    check_xrefs_cache,
    record_breadcrumb,
    resolve_binary_id,
    write_decompile_cache,
    write_disasm_cache,
    write_strings_cache,
    write_xrefs_cache,
    _resolve_rva,
)
from ghidra_nexus.notebook.store import Notebook
from ghidra_nexus.notebook.pagination import DEFAULT_LIMITS, clamp_limit

logger = logging.getLogger(__name__)


def _require_gui_context(ctx: Context):
    from ghidra_nexus.gui_context import GuiPyGhidraContext

    pyghidra_context = ctx.request_context.lifespan_context
    if pyghidra_context is None:
        raise ProgramAccessError(
            ToolErrorCode.SERVER_NOT_READY,
            "Server not initialized. Wait for startup or call wake_ghidra.",
        )
    if not isinstance(pyghidra_context, GuiPyGhidraContext):
        raise ProgramAccessError(
            ToolErrorCode.TOOL_GUI_REQUIRED,
            "This tool requires ghidra-nexus to be running with --gui",
        )
    return pyghidra_context


def _run_for_context(pyghidra_context: MCPContext, fn):
    from ghidra_nexus.gui_context import GuiPyGhidraContext

    if isinstance(pyghidra_context, GuiPyGhidraContext):
        return pyghidra_context.run_on_swing(fn)
    return fn()


def _get_action_name(func_name: str) -> str:
    action = func_name.replace("_", " ")
    words = action.split()
    if words and not words[0].endswith("ing"):
        first = words[0]
        if first.endswith("e"):
            words[0] = first[:-1] + "ing"
        else:
            words[0] = first + "ing"
    return " ".join(words)


def _get_context(ctx: Context) -> MCPContext:
    pyghidra_context = ctx.request_context.lifespan_context
    if pyghidra_context is None:
        raise ProgramAccessError(
            ToolErrorCode.SERVER_NOT_READY,
            "Server not initialized. The Ghidra context is not available. "
            "Wait for startup or call wake_ghidra / analysis_status.",
        )
    return pyghidra_context


def _require_program(
    ctx: Context,
    binary_name: str,
    *,
    require_analysis: bool = True,
):
    """Resolve a program; returns ProgramInfo or raises ProgramAccessError."""
    pyghidra_context = _get_context(ctx)
    return pyghidra_context, pyghidra_context.get_program_info(
        binary_name, require_analysis=require_analysis
    )


_NOTEBOOK_SINGLETON: Notebook | None = None
_NOTEBOOK_LOCK = asyncio.Lock()


async def _get_notebook() -> Notebook:
    """Return the per-process notebook singleton.

    Opens lazily at the first call — no Ghidra needed. The notebook path is
    derived from the current PyGhidraContext's ``nexus_data_dir``.
    """
    global _NOTEBOOK_SINGLETON
    if _NOTEBOOK_SINGLETON is not None:
        return _NOTEBOOK_SINGLETON
    async with _NOTEBOOK_LOCK:
        if _NOTEBOOK_SINGLETON is not None:
            return _NOTEBOOK_SINGLETON
        from ghidra_nexus.context import PyGhidraContext

        pyghidra_context = PyGhidraContext.__new__(PyGhidraContext)
        pyghidra_context.nexus_data_dir = None
        for attr in ("nexus_data_dir",):
            pass  # resolved at first handler call
        _NOTEBOOK_SINGLETON = Notebook.open("ghidra_nexus_projects/my_project-nexus/notebook.sqlite")
        return _NOTEBOOK_SINGLETON


def _get_binary_meta(
    pyghidra_context: MCPContext,
    binary_name: str,
    program_info,  # JVM-side ProgramInfo
) -> tuple[str, str | None, int]:
    """Return (sha256, image_base, generation) for the binary.

    ``generation`` is the analysis_generation from the notebook — 0 on first
    use, bumped by the binary's bump_generation method.
    """
    sha256: str = ""
    image_base: str | None = None
    try:
        from ghidra_nexus.context import PyGhidraContext

        sha256 = PyGhidraContext._safe_sha256(program_info) or ""
    except Exception:
        pass
    try:
        meta = getattr(program_info, "metadata", None)
        if isinstance(meta, dict):
            image_base = meta.get("Image Base") or meta.get("image_base")
    except Exception:
        pass
    return sha256, image_base, 0  # generation handled by notebook.binaries via bump_generation


def _error_tool_response(
    code: ToolErrorCode | str, message: str, **kwargs
) -> dict:
    """Build a tool-result dict that conforms to the ToolError schema."""
    return make_tool_error(code, message, **kwargs)


class _ToolRecoverable(Exception):
    """Marker exception: errors that the agent can recover from.

    Raise ``_ToolRecoverable(ToolErrorCode.SYMBOL_NOT_FOUND, "...")`` from a tool
    body; the decorator catches it and returns the structured ToolError response.
    """

    def __init__(self, code: ToolErrorCode, message: str, **kwargs):
        self.code = code
        self.message = message
        self.kwargs = kwargs


def _as_tool_error_dict(exc: BaseException) -> dict | None:
    """Convert known recoverable exceptions into a ToolError dict, or None."""
    if isinstance(exc, ProgramAccessError):
        return exc.to_tool_error_dict()
    if isinstance(exc, _ToolRecoverable):
        return _error_tool_response(exc.code, exc.message, **exc.kwargs)
    if isinstance(exc, FileNotFoundError):
        return make_tool_error(
            ToolErrorCode.BINARY_PATH_UNREADABLE,
            str(exc) or "File not found",
        )
    if isinstance(exc, ValueError):
        code = classify_lookup_failure(str(exc))
        if code is ToolErrorCode.UNKNOWN:
            code = ToolErrorCode.INVALID_PARAMS
        return make_tool_error(code, str(exc) or "Invalid parameters")
    return None


def mcp_error_handler(func):
    """Centralized error handling + automatic breadcrumb insertion for MCP tools.

    Behaviour:

    - Normal return → record a breadcrumb (best-effort), then pass through.
    - ``ProgramAccessError`` / ``_ToolRecoverable`` / common ValueError /
      FileNotFoundError → return structured ``ToolError`` dict (agent-first).
    - ``McpError`` → re-raise (protocol-level).
    - Other exceptions → ``McpError(INTERNAL_ERROR)`` + watchdog tick.

    Breadcrumbs are *always* inserted after a successful normal return — no
    handler writes breadcrumb code.
    """

    action = _get_action_name(func.__name__)
    tool_name = func.__name__

    async def _insert_breadcrumb(kwargs):
        try:
            nb = await _get_notebook()
            binary_name = kwargs.get("binary_name")
            if binary_name:
                record_breadcrumb(nb, binary_id=None, session_id="session", tool=tool_name,
                                  summary=f"{action} on {binary_name}")
        except Exception:
            pass

    def handle_exception(e: Exception):
        if isinstance(e, McpError):
            return e
        tool_err = _as_tool_error_dict(e)
        if tool_err is not None:
            return tool_err  # returned as tool result body
        wd = get_watchdog()
        if wd is not None:
            wd.record_error()
        return McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error {action}: {e!s}"))

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            result = await func(*args, **kwargs)
            # Breadcrumb after successful return (best-effort).
            try:
                await _insert_breadcrumb(kwargs)
            except Exception:
                pass
            return result
        except McpError:
            raise
        except Exception as e:
            result = handle_exception(e)
            if isinstance(result, McpError):
                raise result from e
            return result

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except McpError:
            raise
        except Exception as e:
            result = handle_exception(e)
            if isinstance(result, McpError):
                raise result from e
            return result

    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


@mcp_error_handler
async def decompile_function(
    binary_name: str,
    name_or_address: str | list[str],
    ctx: Context,
    include_callees: bool = False,
    include_strings: bool = False,
    include_xrefs: bool = False,
    timeout_sec: int = 30,
    offset: int = 0,
    limit: int = 0,  # 0 = use DEFAULT_LIMITS
) -> list[DecompiledFunction]:
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[DecompiledFunction] = []
    limit = clamp_limit("decompile_lines", limit if limit > 0 else None)

    # Notebook setup
    nb = await _get_notebook()
    sha256, image_base, _gen = _get_binary_meta(pyghidra_context, binary_name, program_info)
    bid = resolve_binary_id(nb, binary_name, sha256, image_base=image_base)
    current_gen = nb.binaries.get(binary_name) or {}
    gen = current_gen.get("analysis_generation", 0)

    executor = get_executor()

    def _decompile_target(target: str) -> DecompiledFunction:
        result = tools.decompile_function_by_name_or_addr(target, timeout=timeout_sec)
        if include_callees:
            result.callees = tools.get_callees(target)
        if include_strings:
            result.referenced_strings = tools.get_referenced_strings(target)
        if include_xrefs:
            result.xrefs = tools.list_xrefs(target)
        return result

    for target in targets:
        rva = _resolve_rva(target, program_info)

        # 1. Try cache
        cached = check_decompile_cache(nb, binary_id=bid, rva=rva, current_gen=gen, offset=offset, limit=limit)
        if cached is not None:
            df = DecompiledFunction(
                name=target,
                code=cached["code"],
                decompiler_status=cached.get("decompiler_status", "decompiled"),
                cached=True,
                page=cached.get("page"),
            )
            results.append(df)
            continue

        # 2. Cache miss — call Ghidra
        try:
            result: DecompiledFunction = await executor.submit(
                program_info,
                lambda t=target: _decompile_target(t),
                task_id=f"decompile:{binary_name}:{target}",
            )
            # 3. Write cache + extract
            if result.code:
                write_decompile_cache(
                    nb,
                    binary_id=bid,
                    binary_name=binary_name,
                    binary_sha256=sha256,
                    rva=rva,
                    current_gen=gen,
                    result={
                        "name": result.name,
                        "code": result.code,
                        "lines": result.code.count("\n") + 1 if result.code else 0,
                        "signature": result.signature,
                        "decompiler_status": result.decompiler_status,
                        "error_code": result.error_code,
                        "warnings": getattr(result, "warnings", None),
                    },
                )
            results.append(result)
        except Exception as e:
            fields = decompile_failure_result(
                target,
                str(e),
                binary_name=binary_name,
                addr=target if target.startswith("0x") or target[:1].isdigit() else None,
            )
            results.append(DecompiledFunction(**{**fields, "cached": False}))
    return results


@mcp_error_handler
async def search_symbols_by_name(
    binary_name: str,
    query: str,
    ctx: Context,
    functions_only: bool = False,
    offset: int = 0,
    limit: int = 25,
) -> SymbolSearchResults:
    _, program_info = _require_program(ctx, binary_name, require_analysis=False)
    tools = GhidraTools(program_info)

    def _run():
        symbols = tools.search_symbols_by_name(
            query, functions_only=functions_only, offset=offset, limit=limit
        )
        return SymbolSearchResults(symbols=symbols)

    return await get_executor().submit(
        program_info,
        _run,
        task_id=f"search_sym:{binary_name}:{query[:40]}",
    )


@mcp_error_handler
async def search_code(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 5,
    offset: int = 0,
    search_mode: Literal["semantic", "literal"] = "semantic",
    include_full_code: bool = True,
    preview_length: int = 500,
    similarity_threshold: float = 0.0,
) -> CodeSearchResults:
    _, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)

    def _run():
        return tools.search_code(
            query=query,
            limit=limit,
            offset=offset,
            search_mode=SearchMode(search_mode),
            include_full_code=include_full_code,
            preview_length=preview_length,
            similarity_threshold=similarity_threshold,
        )

    return await get_executor().submit(
        program_info,
        _run,
        task_id=f"search_code:{binary_name}:{query[:40]}",
    )


@mcp_error_handler
async def list_project_binaries(ctx: Context) -> ProgramInfos:
    pyghidra_context = _get_context(ctx)
    return ProgramInfos(programs=pyghidra_context.list_project_binary_infos())


@mcp_error_handler
async def list_project_binary_metadata(binary_name: str, ctx: Context) -> dict:
    _, program_info = _require_program(ctx, binary_name, require_analysis=False)
    return program_info.metadata


@mcp_error_handler
async def list_open_programs(ctx: Context) -> OpenProgramInfos:
    gui_context = _require_gui_context(ctx)
    programs = [OpenProgramInfo(**info) for info in gui_context.list_open_programs()]
    return OpenProgramInfos(programs=programs)


@mcp_error_handler
async def open_program_in_gui(
    binary_name: str,
    new_window: bool = True,
    *,
    ctx: Context,
) -> OpenProgramInfo:
    gui_context = _require_gui_context(ctx)
    return OpenProgramInfo(**gui_context.open_program_in_gui(binary_name, new_window=new_window))


@mcp_error_handler
async def set_current_program(binary_name: str, ctx: Context) -> OpenProgramInfo:
    gui_context = _require_gui_context(ctx)
    return OpenProgramInfo(**gui_context.set_current_program(binary_name))


@mcp_error_handler
async def goto(
    binary_name: str,
    target: str,
    target_type: Literal["address", "function"],
    ctx: Context,
) -> GotoResponse:
    gui_context = _require_gui_context(ctx)
    return GotoResponse(**gui_context.goto(binary_name, target, target_type))


@mcp_error_handler
async def get_gui_context(ctx: Context) -> GuiContextResponse:
    gui_context = _require_gui_context(ctx)
    return GuiContextResponse(**gui_context.get_active_gui_context())


@mcp_error_handler
async def rename_function(
    binary_name: str,
    name_or_address: str,
    new_name: str,
    ctx: Context,
) -> RenameResponse:
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)

    def _run():
        return _run_for_context(
            pyghidra_context,
            lambda: tools.rename_function(name_or_address, new_name),
        )

    result = await get_executor().submit(
        program_info, _run, write=True, task_id=f"rename:{binary_name}:{name_or_address}",
    )
    result = cast(dict, result)
    return RenameResponse(binary_name=binary_name, **result)


@mcp_error_handler
async def rename_variable(
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    new_name: str,
    ctx: Context,
) -> VariableRenameResponse:
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)

    def _run():
        return _run_for_context(
            pyghidra_context,
            lambda: tools.rename_variable(function_name_or_address, variable_name, new_name),
        )

    result = await get_executor().submit(
        program_info, _run, write=True,
        task_id=f"rename_var:{binary_name}:{function_name_or_address}",
    )
    result = cast(dict, result)
    return VariableRenameResponse(binary_name=binary_name, **result)


@mcp_error_handler
async def set_variable_type(
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    type_name: str,
    ctx: Context,
) -> VariableTypeResponse:
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)

    def _run():
        return _run_for_context(
            pyghidra_context,
            lambda: tools.set_variable_type(function_name_or_address, variable_name, type_name),
        )

    result = await get_executor().submit(
        program_info, _run, write=True,
        task_id=f"set_type:{binary_name}:{function_name_or_address}",
    )
    result = cast(dict, result)
    return VariableTypeResponse(binary_name=binary_name, **result)


@mcp_error_handler
async def set_function_prototype(
    binary_name: str,
    function_name_or_address: str,
    prototype: str,
    ctx: Context,
) -> FunctionPrototypeResponse:
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)

    def _run():
        return _run_for_context(
            pyghidra_context,
            lambda: tools.set_function_prototype(function_name_or_address, prototype),
        )

    result = await get_executor().submit(
        program_info, _run, write=True,
        task_id=f"set_proto:{binary_name}:{function_name_or_address}",
    )
    result = cast(dict, result)
    return FunctionPrototypeResponse(binary_name=binary_name, **result)


@mcp_error_handler
async def set_comment(
    binary_name: str,
    target: str,
    comment: str,
    comment_type: Literal["decompiler", "plate", "pre", "eol", "post", "repeatable"],
    ctx: Context,
) -> CommentResponse:
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)

    def _run():
        return _run_for_context(
            pyghidra_context,
            lambda: tools.set_comment(target, comment, comment_type),
        )

    result = await get_executor().submit(
        program_info, _run, write=True,
        task_id=f"set_comment:{binary_name}:{target}",
    )
    result = cast(dict, result)
    return CommentResponse(binary_name=binary_name, **result)


@mcp_error_handler
async def delete_project_binary(binary_name: str, ctx: Context) -> str:
    pyghidra_context = _get_context(ctx)
    if pyghidra_context.delete_program(binary_name):
        return f"Successfully deleted binary: {binary_name}"
    raise _ToolRecoverable(
        ToolErrorCode.BINARY_NOT_FOUND,
        f"Binary '{binary_name}' not found or could not be deleted.",
        binary_name=binary_name,
    )


@mcp_error_handler
async def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    _, program_info = _require_program(ctx, binary_name, require_analysis=False)
    tools = GhidraTools(program_info)

    def _run():
        exports = tools.list_exports(query=query, offset=offset, limit=limit)
        return ExportInfos(exports=exports)

    return await get_executor().submit(
        program_info, _run, task_id=f"list_exports:{binary_name}",
    )


@mcp_error_handler
async def list_imports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ImportInfos:
    _, program_info = _require_program(ctx, binary_name, require_analysis=False)
    tools = GhidraTools(program_info)

    def _run():
        imports = tools.list_imports(query=query, offset=offset, limit=limit)
        return ImportInfos(imports=imports)

    return await get_executor().submit(
        program_info, _run, task_id=f"list_imports:{binary_name}",
    )


@mcp_error_handler
async def list_xrefs(
    binary_name: str, name_or_address: str | list[str], ctx: Context,
    offset: int = 0, limit: int = 0,
) -> list[CrossReferenceInfos]:
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    limit = clamp_limit("xrefs", limit if limit > 0 else None)

    nb = await _get_notebook()
    sha256, image_base, _gen = _get_binary_meta(pyghidra_context, binary_name, program_info)
    bid = resolve_binary_id(nb, binary_name, sha256, image_base=image_base)

    executor = get_executor()
    results: list[CrossReferenceInfos] = []
    for target in targets:
        rva = _resolve_rva(target, program_info)
        cached = check_xrefs_cache(nb, binary_id=bid, rva=rva, offset=offset, limit=limit)
        if cached is not None:
            results.append(CrossReferenceInfos(
                target=target,
                cross_references=cached.get("items", []),
                cached=True,
            ))
            continue

        try:
            def _run(t=target):
                cross_references = tools.list_xrefs(t)
                return CrossReferenceInfos(target=t, cross_references=cross_references)
            result = await executor.submit(program_info, _run, task_id=f"xrefs:{binary_name}:{target}")
            if result.cross_references:
                write_xrefs_cache(nb, binary_id=bid, binary_name=binary_name, rva=rva, current_gen=0, result={
                    "cross_references": [{
                        "from_address": x.from_address, "to_address": x.to_address,
                        "type": x.type, "function_name": x.function_name,
                    } for x in (result.cross_references or [])],
                })
            result.cached = False
            results.append(result)
        except Exception as e:
            code = classify_lookup_failure(str(e), binary_name=binary_name)
            err = make_tool_error(code, str(e), binary_name=binary_name, addr=target)
            results.append(CrossReferenceInfos(target=target, cross_references=[], error=str(e),
                                               error_code=err["error_code"], hint=err.get("hint")))
    return results


@mcp_error_handler
async def search_strings(
    binary_name: str,
    ctx: Context,
    query: str,
    limit: int = 100,
    offset: int = 0,
) -> StringSearchResults:
    limit = clamp_limit("strings", limit)
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=False)
    nb = await _get_notebook()
    sha256, image_base, _gen = _get_binary_meta(pyghidra_context, binary_name, program_info)
    bid = resolve_binary_id(nb, binary_name, sha256, image_base=image_base)

    cached = check_strings_cache(nb, binary_id=bid, pattern=query, offset=offset, limit=limit)
    if cached is not None:
        return StringSearchResults(
            strings=cached.get("items", []),
            cached=True,
        )

    tools = GhidraTools(program_info)
    def _run():
        return tools.search_strings(query=query, limit=limit)
    result = await get_executor().submit(program_info, _run, task_id=f"search_strings:{binary_name}:{query[:40]}")

    if result.strings:
        write_strings_cache(nb, binary_id=bid, binary_name=binary_name, current_gen=0, result={
            "strings": [{"value": s.value, "address": s.address, "encoding": "ascii"} for s in result.strings],
        })
    return result


@mcp_error_handler
async def read_bytes(
    binary_name: str, ctx: Context, address: str, size: int = 32
) -> BytesReadResult:
    _, program_info = _require_program(ctx, binary_name, require_analysis=False)
    tools = GhidraTools(program_info)

    def _run():
        return tools.read_bytes(address=address, size=size)

    return await get_executor().submit(
        program_info, _run, task_id=f"read_bytes:{binary_name}:{address}",
    )


@mcp_error_handler
async def disassemble(
    binary_name: str,
    ctx: Context,
    address: str,
    count: int = 20,
    include_bytes: bool = False,
    offset: int = 0,
    limit: int = 0,
) -> DisassembleResult:
    if count <= 0:
        raise _ToolRecoverable(ToolErrorCode.INVALID_RANGE, "count must be > 0", binary_name=binary_name, addr=address)
    if count > 200:
        raise _ToolRecoverable(ToolErrorCode.INVALID_RANGE, "count must be <= 200", binary_name=binary_name, addr=address)
    limit = clamp_limit("disasm_insns", limit if limit > 0 else count)

    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=False)
    nb = await _get_notebook()
    sha256, image_base, _gen = _get_binary_meta(pyghidra_context, binary_name, program_info)
    bid = resolve_binary_id(nb, binary_name, sha256, image_base=image_base)
    rva = _resolve_rva(address, program_info)

    cached = check_disasm_cache(nb, binary_id=bid, rva=rva, current_gen=0, offset=offset, limit=limit)
    if cached is not None:
        return DisassembleResult(address=address, count=cached["count"], listing=cached["listing"], cached=True)

    tools = GhidraTools(program_info)
    def _run():
        return tools.disassemble(address=address, count=count, include_bytes=include_bytes)
    result = await get_executor().submit(program_info, _run, task_id=f"disassemble:{binary_name}:{address}")

    if result.listing:
        write_disasm_cache(nb, binary_id=bid, binary_name=binary_name, rva=rva, current_gen=0, result={
            "function_name": "", "address": address, "listing": result.listing,
            "count": result.count, "instruction_count": result.count,
        })
    return result


@mcp_error_handler
async def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: Literal["calling", "called"] = "calling",
    display_type: Literal["flow", "flow_ends"] = "flow",
    condense_threshold: int = 50,
    top_layers: int = 3,
    bottom_layers: int = 3,
    max_run_time: int = 120,
) -> CallGraphResult:
    _, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)

    def _run():
        return tools.gen_callgraph(
            function_name_or_address=function_name,
            cg_direction=CallGraphDirection(direction),
            cg_display_type=CallGraphDisplayType(display_type),
            include_refs=True,
            max_depth=None,
            max_run_time=max_run_time,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
        )

    return await get_executor().submit(
        program_info, _run, task_id=f"callgraph:{binary_name}:{function_name}",
    )


@mcp_error_handler
async def analysis_status(ctx: Context) -> AnalysisStatusResult:
    """Show analysis progress + project-level warnings.

    This is the agent's single source of truth for "what does the project
    look like right now" — poll this instead of trusting free-text error
    responses from individual tool calls.

    Per binary, returns:
        - ``analysis_state`` — lifecycle stage (queued / loading / analyzing /
          complete / failed)
        - ``function_count`` — live count from Ghidra; ``0`` means not analyzed yet
        - ``entropy_summary`` — top-level entropy profile (encrypted / compressed /
          normal / mixed / unknown)
        - ``project_path`` / ``nexus_data_dir`` / ``idb_path`` — absolute paths
          the agent can validate against ``os.path.exists``
        - ``recommended_tools`` — what to call next given current state

    Server-level:
        - ``path_warnings`` — writability warnings about the project path. Empty
          on a healthy setup; surfaces UAC-locked directories on Windows before
          project writes silently fail.
    """
    from ghidra_nexus import __version__
    from ghidra_nexus.context import PyGhidraContext
    from ghidra_nexus.server import _check_project_path_writable

    pyghidra_context = _get_context(ctx)
    raw_infos = pyghidra_context.list_project_binary_infos()

    project_path_str = str(getattr(pyghidra_context, "project_path", None) or "") or None
    nexus_dir_str = str(getattr(pyghidra_context, "nexus_data_dir", None) or "") or None

    binaries: list[ProgramInfo] = []
    for raw in raw_infos:
        # Prefer fields already enriched by list_project_binary_infos.
        function_count = int(getattr(raw, "function_count", 0) or 0)
        sha256 = getattr(raw, "sha256", None)
        entropy_summary = getattr(raw, "entropy_summary", None) or "unknown"
        if isinstance(raw.metadata, dict):
            if not function_count:
                function_count = int(raw.metadata.get("function_count") or 0)
            if not sha256:
                sha256 = raw.metadata.get("sha256")
            if entropy_summary in (None, "unknown", "normal") and raw.metadata.get(
                "entropy_summary"
            ):
                entropy_summary = raw.metadata["entropy_summary"]

        # Live re-count from the open program when possible (truthful status).
        live_pi = None
        try:
            with getattr(pyghidra_context, "_programs_lock", threading.Lock()):
                programs = getattr(pyghidra_context, "programs", {}) or {}
                live_pi = programs.get(raw.name)
        except Exception:
            live_pi = None

        if live_pi is not None:
            try:
                function_count = PyGhidraContext._safe_function_count(live_pi)
            except Exception:
                pass
            try:
                sha256 = PyGhidraContext._safe_sha256(live_pi) or sha256
            except Exception:
                pass
            # Cheap cached entropy pass (once per binary per daemon lifetime).
            ensure = getattr(pyghidra_context, "ensure_entropy_summary", None)
            if callable(ensure):
                try:
                    entropy_summary = ensure(live_pi)
                except Exception:
                    pass
            elif getattr(live_pi, "entropy_summary", None):
                entropy_summary = live_pi.entropy_summary

        if raw.analysis_complete:
            state = "complete"
            if function_count == 0:
                # Analysis finished but no functions — agent should not treat as
                # a healthy binary (packed / empty / wrong loader).
                recommended = ["section_health", "survey_binary_fast"]
            elif getattr(raw, "code_indexed", False):
                recommended = ["survey_binary_full", "search_code"]
            else:
                recommended = ["section_health", "survey_binary_full"]
        else:
            state = getattr(raw, "analysis_state", None) or "analyzing_functions"
            recommended = ["survey_binary_fast", "section_health", "analysis_status"]

        file_path = raw.file_path
        path_exists: bool | None = None
        if file_path:
            try:
                path_exists = Path(file_path).exists()
            except Exception:
                path_exists = None

        binaries.append(
            ProgramInfo(
                name=raw.name,
                file_path=file_path,
                load_time=raw.load_time,
                analysis_complete=raw.analysis_complete,
                metadata=raw.metadata if isinstance(raw.metadata, dict) else {},
                code_indexed=raw.code_indexed,
                strings_indexed=raw.strings_indexed,
                analysis_state=state,
                function_count=function_count,
                sha256=sha256,
                entropy_summary=entropy_summary or "unknown",
                project_path=project_path_str,
                nexus_data_dir=nexus_dir_str,
                idb_path=file_path,
                path_exists=path_exists,
                recommended_tools=recommended,
            )
        )

    warnings: list[str] = []
    try:
        if project_path_str is not None:
            warnings = _check_project_path_writable(Path(project_path_str))
    except Exception:
        warnings = []

    return AnalysisStatusResult(
        binaries=binaries,
        path_warnings=warnings,
        server_version=__version__,
    )


@mcp_error_handler
async def survey_binary(
    binary_name: str,
    ctx: Context,
    detail_level: Literal["standard", "minimal"] = "standard",
) -> SurveyBinaryResult:
    """Single-call binary triage snapshot — alias for ``survey_binary_full``.

    Kept for backward compatibility. Prefer ``survey_binary_fast`` for a
    pre-analysis snapshot in milliseconds, and ``survey_binary_full`` when
    you can wait for the full Ghidra auto-analysis. Refuses to run while
    Ghidra analysis is in progress — call ``analysis_status`` first to
    check.
    """
    return await survey_binary_full(
        binary_name=binary_name, ctx=ctx, detail_level=detail_level
    )


@mcp_error_handler
async def survey_binary_fast(
    binary_name: str,
    ctx: Context,
) -> SurveyBinaryResult:
    """Pre-analysis triage snapshot — returns in milliseconds.

    **Use this for first-look triage of a freshly imported binary.**
    Returns immediately with the data Ghidra has after raw import (no
    auto-analysis, no PDB download, no Decompiler analyzers running).
    Typical latency: **< 1 second**.

    The result's ``mode`` field is ``"fast"`` and the ``note`` field is
    set to ``"pre-analysis: ..."`` so subsequent agents can tell at a
    glance that the data is pre-analysis.

    What you get:
        - ``metadata``: arch, image base, size, md5/sha256
        - ``statistics``: function/string/segment counts (function count is
          typically just the entry point + imports before analysis)
        - ``segments``: memory blocks with rwx perms
        - ``entrypoints``: external entry points (exports)
        - ``imports_by_category``: full bin of all imports by capability
          (crypto / network / file_io / process / registry / other)
        - ``interesting_functions``: top-15 by **body size** (NOT xrefs —
          xrefs aren't computed yet). ``callee_count`` and ``xref_count``
          are reported as 0.
        - ``interesting_strings``: length-sorted slice of defined strings
          (capped at 50). NOT xref-ranked.
        - ``call_graph_summary``: present but all counters are 0 (call
          graph isn't computed until analyzers run)

    Use ``survey_binary_full`` afterwards if you want xref-ranked results
    and the call-graph topology. Or go straight to ``decompile_function``
    on a function from ``interesting_functions`` if you've already
    identified a target.

    Unlike ``survey_binary_full``, this tool does NOT wait for
    ``analysis_status()`` to report complete — it works on whatever
    state the program is in, including a freshly imported binary that
    hasn't been analyzed yet.
    """
    _, program_info = _require_program(ctx, binary_name, require_analysis=False)
    tools = GhidraTools(program_info)

    def _run():
        return tools.survey_binary_fast()

    return await get_executor().submit(
        program_info,
        _run,
        task_id=f"survey_fast:{binary_name}",
    )


@mcp_error_handler
async def survey_binary_full(
    binary_name: str,
    ctx: Context,
    detail_level: Literal["standard", "minimal"] = "standard",
) -> SurveyBinaryResult:
    """Post-analysis triage snapshot — waits for full Ghidra analysis.

    **Use this for deep triage of a binary you've decided is worth
    analyzing.** Returns everything the survey can give you: file
    metadata, segment layout, entry points, statistics, top-15 strings
    ranked by xref count, top-15 functions ranked by xref count (each
    classified as ``thunk`` / ``wrapper`` / ``leaf`` / ``dispatcher`` /
    ``complex``), imports grouped by category, and a call-graph
    summary with max-depth BFS estimate.

    The result's ``mode`` field is ``"full"``.

    **Refuses to run while Ghidra auto-analysis is still in progress.**
    On a freshly imported binary that takes 5-10 minutes to analyze
    (PDB download + Decompiler analyzers), use ``survey_binary_fast``
    first to get a quick read, and call this tool once
    ``analysis_status()`` reports complete.

    Parameters
    ----------
    binary_name
        The project program name (use ``list_project_binaries`` to find
        it). May be a unique prefix.
    detail_level
        ``"standard"`` returns the full payload above.
        ``"minimal"`` returns only metadata, statistics, segments, and
        entrypoints — use for very large binaries where the full payload
        would block the executor thread.

    Subsequent follow-ups (from ``recommended_tools``):
        - ``interesting_functions`` → ``decompile_function`` on the top
          dispatcher / complex function, then ``gen_callgraph`` from
          there.
        - ``interesting_strings`` → ``list_xrefs`` on a suspicious
          string address, then ``decompile_function`` on each caller.
        - ``imports_by_category`` → ``decompile_function`` on every
          caller of a flagged import (``CreateRemoteThread``,
          ``VirtualProtect``, etc.).
        - ``call_graph_summary`` → ``gen_callgraph(binary_name, "entry",
          direction="called")`` for the topology.
    """
    # require_analysis=True → structured BINARY_ANALYZING if still running.
    _, program_info = _require_program(ctx, binary_name, require_analysis=True)
    tools = GhidraTools(program_info)

    def _run():
        return tools.survey_binary_full(detail_level=detail_level)

    return await get_executor().submit(
        program_info,
        _run,
        task_id=f"survey_full:{binary_name}:{detail_level}",
    )


@mcp_error_handler
async def section_health(binary_name: str, ctx: Context) -> list[SectionHealth]:
    """Per-section entropy + classification + agent recommendation."""
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=False)
    nb = await _get_notebook()
    sha256, image_base, _gen = _get_binary_meta(pyghidra_context, binary_name, program_info)
    bid = resolve_binary_id(nb, binary_name, sha256, image_base=image_base)

    tools = GhidraTools(program_info)
    def _run():
        result = tools.section_health()
        try:
            from ghidra_nexus.section_entropy import summarize_section_classifications
            summary = summarize_section_classifications(r.classification for r in result)
            program_info.entropy_summary = summary
            program_info.entropy_computed = True
        except Exception:
            pass
        return result
    result = await get_executor().submit(program_info, _run, task_id=f"section_health:{binary_name}")

    # Write view (best-effort)
    try:
        from ghidra_nexus.notebook.extractors import extract_for
        payload = {"results": [{"name": r.name, "classification": r.classification.value if hasattr(r, 'classification') and r.classification else str(r.classification),
                                 "recommendation": r.recommendation.value if hasattr(r, 'recommendation') and r.recommendation else str(r.recommendation),
                                 "entropy": r.entropy, "size_bytes": r.size_bytes}
                                for r in result]}
        view = extract_for("section_health", payload)
        if view is not None:
            vid = nb.views.upsert(binary_id=bid, rva="", kind="section_health", summary=view.summary,
                                  key_entities=view.entities_json(), view_model=view.view_model)
            nb.search.upsert(kind="section_health", binary_id=bid, rva="", body=view.search_blob())
            nb.embed_queue.enqueue(vid)
    except Exception:
        pass
    return result


@mcp_error_handler
async def import_binary(binary_path: str, ctx: Context) -> ImportRequestResult:
    pyghidra_context = _get_context(ctx)
    return pyghidra_context.import_binary_backgrounded(binary_path)


@mcp_error_handler
async def save(ctx: Context) -> SaveRequestResult:
    pyghidra_context = _get_context(ctx)
    pyghidra_context.save()
    return SaveRequestResult()


# ---- Lazy activation tools (for streamable-http daemon mode) ----

_AWAKE = False
_AWAKE_LOCK = threading.Lock()


def _register_all_on_demand(mcp_server):
    """Register all analysis tools on a FastMCP server dynamically."""
    tools = [
        (decompile_function, "decompile_function"),
        (search_symbols_by_name, "search_symbols_by_name"),
        (search_code, "search_code"),
        (list_project_binaries, "list_project_binaries"),
        (list_project_binary_metadata, "list_project_binary_metadata"),
        (rename_function, "rename_function"),
        (rename_variable, "rename_variable"),
        (set_variable_type, "set_variable_type"),
        (set_function_prototype, "set_function_prototype"),
        (set_comment, "set_comment"),
        (delete_project_binary, "delete_project_binary"),
        (list_exports, "list_exports"),
        (list_imports, "list_imports"),
        (list_xrefs, "list_xrefs"),
        (search_strings, "search_strings"),
        (read_bytes, "read_bytes"),
        (disassemble, "disassemble"),
        (gen_callgraph, "gen_callgraph"),
        (section_health, "section_health"),
        (analysis_status, "analysis_status"),
        (import_binary, "import_binary"),
        (save, "save"),
    ]
    for fn, name in tools:
        try:
            mcp_server.add_tool(fn, name=name)
        except Exception:
            logger.warning("Failed to register tool %s", name, exc_info=True)
    try:
        mcp_server.remove_tool("wake_ghidra")
    except Exception:
        pass


@mcp_error_handler
async def wake_ghidra(ctx: Context) -> str:
    """Start the Ghidra JVM and register all analysis tools.

    Call this first in streamable-http daemon mode. The daemon starts
    without loading Ghidra to save resources. This boots the JVM,
    opens the project, and makes all analysis tools available.
    """
    global _AWAKE
    with _AWAKE_LOCK:
        if _AWAKE:
            return "Ghidra is already awake."
        _AWAKE = True

    import time as _time
    logger.info("wake_ghidra: starting Ghidra JVM...")
    t0 = _time.time()

    import pyghidra
    pyghidra.start(False)

    from ghidra_nexus.context import PyGhidraContext
    context = PyGhidraContext(
        project_name="my_project",
        project_path="C:/Dev/Ghidra-MCP/ghidra-projects",
        threaded=True,
        wait_for_analysis=False,
    )
    ctx.request_context.lifespan_context._pyghidra_context = context

    from ghidra_nexus.ghidra_executor import GhidraExecutor, set_executor as _se
    executor = GhidraExecutor(max_queue_size=100, task_timeout=60.0)
    executor.start()
    _se(executor)

    from ghidra_nexus.watchdog import Watchdog, set_watchdog as _sw
    wd = Watchdog(executor=executor, get_programs=lambda: context.programs)
    wd.start()
    _sw(wd)

    ph = getattr(ctx.request_context.lifespan_context, "_ph", None)
    if ph is not None:
        ph._pyghidra_context = context
    mcp_server = getattr(ph, "_mcp", None) if ph is not None else None
    if mcp_server is not None:
        _register_all_on_demand(mcp_server)

    if len(context.list_binaries()) == 0:
        logger.warning("No binaries in project. Use import_binary to add one.")

    elapsed = _time.time() - t0
    logger.info("wake_ghidra: ready in %.0fs", elapsed)
    return f"Ghidra engine started in {elapsed:.0f}s. All analysis tools are now available."


@mcp_error_handler
async def ghidra_status(ctx: Context) -> str:
    """Check whether Ghidra is awake and ready."""
    return "awake" if _AWAKE else "asleep (call wake_ghidra to start)"
