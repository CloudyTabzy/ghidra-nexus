"""
MCP Tool handlers for ghidra-nexus.

All handlers are async and dispatch Ghidra work through the GhidraExecutor
background thread for thread safety.
"""

import asyncio
import functools
import logging
import threading
from typing import Literal, cast

from mcp.server.fastmcp import Context
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from ghidra_nexus.context_protocol import MCPContext
from ghidra_nexus.ghidra_executor import get_executor
from ghidra_nexus.models import (
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
    ProgramInfos,
    RenameResponse,
    SaveRequestResult,
    SearchMode,
    StringSearchResults,
    SurveyBinaryResult,
    SymbolSearchResults,
    VariableRenameResponse,
    VariableTypeResponse,
)
from ghidra_nexus.tools import GhidraTools
from ghidra_nexus.watchdog import get_watchdog

logger = logging.getLogger(__name__)


def _require_gui_context(ctx: Context):
    from ghidra_nexus.gui_context import GuiPyGhidraContext

    pyghidra_context = ctx.request_context.lifespan_context
    if pyghidra_context is None:
        raise McpError(
            ErrorData(
                code=INTERNAL_ERROR,
                message="Server not initialized. The Ghidra context is not available yet. "
                "Wait for the server startup to complete.",
            )
        )
    if not isinstance(pyghidra_context, GuiPyGhidraContext):
        raise ValueError("This tool requires ghidra-nexus to be running with --gui")
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
        raise McpError(
            ErrorData(
                code=INTERNAL_ERROR,
                message="Server not initialized. The Ghidra context is not available. "
                "Wait for the server startup to complete.",
            )
        )
    return pyghidra_context


def mcp_error_handler(func):
    """Decorator that provides centralized error handling for MCP tools."""

    action = _get_action_name(func.__name__)

    def handle_error(e):
        if isinstance(e, McpError):
            return e
        if isinstance(e, (ValueError, FileNotFoundError, AttributeError)):
            return McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))
        wd = get_watchdog()
        if wd is not None:
            wd.record_error()
        return McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error {action}: {e!s}"))

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

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
) -> list[DecompiledFunction]:
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[DecompiledFunction] = []

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
        try:
            result = await executor.submit(
                program_info,
                lambda t=target: _decompile_target(t),
                task_id=f"decompile:{binary_name}:{target}",
            )
            results.append(result)
        except Exception as e:
            results.append(DecompiledFunction(name=target, code="", error=str(e)))
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    else:
        raise McpError(
            ErrorData(
                code=INVALID_PARAMS,
                message=f"Binary '{binary_name}' not found or could not be deleted.",
            )
        )


@mcp_error_handler
async def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)

    def _run():
        imports = tools.list_imports(query=query, offset=offset, limit=limit)
        return ImportInfos(imports=imports)

    return await get_executor().submit(
        program_info, _run, task_id=f"list_imports:{binary_name}",
    )


@mcp_error_handler
async def list_xrefs(
    binary_name: str, name_or_address: str | list[str], ctx: Context
) -> list[CrossReferenceInfos]:
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address

    executor = get_executor()
    results: list[CrossReferenceInfos] = []
    for target in targets:
        try:
            def _run(t=target):
                cross_references = tools.list_xrefs(t)
                return CrossReferenceInfos(target=t, cross_references=cross_references)

            result = await executor.submit(
                program_info, _run, task_id=f"xrefs:{binary_name}:{target}",
            )
            results.append(result)
        except Exception as e:
            results.append(CrossReferenceInfos(target=target, cross_references=[], error=str(e)))
    return results


@mcp_error_handler
async def search_strings(
    binary_name: str,
    ctx: Context,
    query: str,
    limit: int = 100,
) -> StringSearchResults:
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)

    def _run():
        return tools.search_strings(query=query, limit=limit)

    return await get_executor().submit(
        program_info, _run, task_id=f"search_strings:{binary_name}:{query[:40]}",
    )


@mcp_error_handler
async def read_bytes(
    binary_name: str, ctx: Context, address: str, size: int = 32
) -> BytesReadResult:
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
) -> DisassembleResult:
    if count <= 0:
        raise ValueError("count must be > 0")
    if count > 200:
        raise ValueError("count must be <= 200")
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)

    def _run():
        return tools.disassemble(address=address, count=count, include_bytes=include_bytes)

    return await get_executor().submit(
        program_info, _run, task_id=f"disassemble:{binary_name}:{address}",
    )


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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
async def analysis_status(ctx: Context) -> ProgramInfos:
    """Show analysis progress for all binaries in the project.

    Use this before calling decompile or search tools to check whether
    each binary has finished Ghidra analysis and ChromaDB indexing.
    'code_indexed' means semantic search is available.
    """
    pyghidra_context = _get_context(ctx)
    return ProgramInfos(programs=pyghidra_context.list_project_binary_infos())


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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
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
    pyghidra_context = _get_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)

    if not program_info.analysis_complete:
        raise McpError(
            ErrorData(
                code=INVALID_PARAMS,
                message=(
                    f"Ghidra analysis for '{binary_name}' is still in progress. "
                    "Call survey_binary_fast for a pre-analysis snapshot, or "
                    "wait for analysis_status to report complete and then "
                    "retry survey_binary_full."
                ),
            )
        )

    def _run():
        return tools.survey_binary_full(detail_level=detail_level)

    return await get_executor().submit(
        program_info,
        _run,
        task_id=f"survey_full:{binary_name}:{detail_level}",
    )


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
