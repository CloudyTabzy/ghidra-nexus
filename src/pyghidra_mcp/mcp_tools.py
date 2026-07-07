"""
MCP Tool handlers for pyghidra-mcp.

All handlers are async and dispatch Ghidra work through the GhidraExecutor
background thread for thread safety.
"""

import asyncio
import functools
import logging
from typing import Literal, cast

from mcp.server.fastmcp import Context
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_mcp.context_protocol import MCPContext
from pyghidra_mcp.ghidra_executor import get_executor
from pyghidra_mcp.models import (
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
    SymbolSearchResults,
    VariableRenameResponse,
    VariableTypeResponse,
)
from pyghidra_mcp.tools import GhidraTools
from pyghidra_mcp.watchdog import get_watchdog

logger = logging.getLogger(__name__)


def _require_gui_context(ctx: Context):
    from pyghidra_mcp.gui_context import GuiPyGhidraContext

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
        raise ValueError("This tool requires pyghidra-mcp to be running with --gui")
    return pyghidra_context


def _run_for_context(pyghidra_context: MCPContext, fn):
    from pyghidra_mcp.gui_context import GuiPyGhidraContext

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
async def import_binary(binary_path: str, ctx: Context) -> ImportRequestResult:
    pyghidra_context = _get_context(ctx)
    return pyghidra_context.import_binary_backgrounded(binary_path)


@mcp_error_handler
async def save(ctx: Context) -> SaveRequestResult:
    pyghidra_context = _get_context(ctx)
    pyghidra_context.save()
    return SaveRequestResult()
