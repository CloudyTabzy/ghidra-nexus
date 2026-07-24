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
import hashlib
import logging
import sqlite3
import threading
import time as _time
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from ghidra_nexus.notebook.store import Notebook

from mcp.server.fastmcp import Context
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, ErrorData

from ghidra_nexus.context_protocol import MCPContext
from ghidra_nexus.errors import (
    ProgramAccessError,
    ToolErrorCode,
    classify_lookup_failure,
    decompile_failure_result,
    make_tool_error,
)
from ghidra_nexus.ghidra_executor import get_executor
from ghidra_nexus.models import (
    AnalysisStatusResult,
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CallSiteAnalysisResult,
    CallSiteInfo,
    CallsiteOverrideResult,
    CodeSearchResult,
    CodeSearchResults,
    CommentResponse,
    CrossReferenceInfos,
    DecompiledFunction,
    DisassembleResult,
    ExportInfos,
    FunctionPrototypeResponse,
    GotoResponse,
    GuiContextResponse,
    HookStubResult,
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
    VerifyPortResult,
)
from ghidra_nexus.notebook.cache import (
    _resolve_rva,
    check_callsite_cache,
    check_decompile_cache,
    check_disasm_cache,
    check_strings_cache,
    check_xrefs_cache,
    record_breadcrumb,
    resolve_binary_id,
    write_callsite_cache,
    write_decompile_cache,
    write_disasm_cache,
    write_strings_cache,
    write_xrefs_cache,
)
from ghidra_nexus.notebook.pagination import clamp_limit, window_list
from ghidra_nexus.notebook.store import Notebook
from ghidra_nexus.tools import GhidraTools
from ghidra_nexus.watchdog import get_watchdog

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
_SESSION_ID = __import__("uuid").uuid4().hex[:12]  # per-daemon session id for breadcrumbs


async def _get_notebook(pyghidra_context=None) -> Notebook:
    """Return the notebook, preferring the context's instance.

    The context already owns a Notebook connection; re-using it avoids opening a
    second SQLite handle to the same WAL file, which can deadlock under the
    stdio transport's tight polling loop. Falls back to the per-process
    singleton for tests and callers without a context.

    Path resolution order (only used when no context notebook is available):
      1. ``NEXUS_NOTEBOOK_PATH`` env var (test isolation; highest priority)
      2. ``pyghidra_context.nexus_data_dir / notebook.sqlite`` (production)
      3. Default ``ghidra_nexus_projects/my_project-nexus/notebook.sqlite``
    """
    global _NOTEBOOK_SINGLETON
    # Prefer the context-owned notebook to keep one SQLite connection.
    # Only trust a real Notebook instance; Mock objects from unit tests must
    # fall through to the singleton path so the test tmp_path notebook is used.
    if pyghidra_context is not None:
        context_nb = getattr(pyghidra_context, "_get_notebook", None)
        if callable(context_nb):
            nb = context_nb()
            if isinstance(nb, Notebook):
                return nb
    if _NOTEBOOK_SINGLETON is not None:
        return _NOTEBOOK_SINGLETON
    async with _NOTEBOOK_LOCK:
        if _NOTEBOOK_SINGLETON is not None:
            return _NOTEBOOK_SINGLETON
        import os as _os
        env_path = _os.environ.get("NEXUS_NOTEBOOK_PATH")
        if env_path:
            path = env_path
        else:
            path = "ghidra_nexus_projects/my_project-nexus/notebook.sqlite"
            if pyghidra_context is not None:
                ndd = getattr(pyghidra_context, "nexus_data_dir", None)
                if ndd:
                    from pathlib import Path as _Path
                    path = str(_Path(ndd) / "notebook.sqlite")
        _NOTEBOOK_SINGLETON = Notebook.open(path)
        # Lazily start the embed worker so FTS writes get drained to vec.
        # Best-effort: any failure (missing deps, sqlite-vec unavailable)
        # leaves FTS-only mode intact.
        if not _os.environ.get("NEXUS_DISABLE_EMBED_WORKER"):
            try:
                _get_embed_worker()
            except Exception:
                pass
        return _NOTEBOOK_SINGLETON


# ---------------------------------------------------------------------------
# Embed worker (Phase 3) — drains embed_queue in a daemon thread.
# ---------------------------------------------------------------------------
_EMBED_WORKER = None
_EMBED_WORKER_LOCK = threading.Lock()


def _get_embed_worker() -> "EmbedWorker | None":
    """Return the embed worker singleton, creating it lazily.

    Returns ``None`` if the embed queue is empty / vec unavailable; the worker
    still attaches but stays idle. ``start()`` is idempotent — calling twice
    is safe. Disabled by setting env ``NEXUS_DISABLE_EMBED_WORKER=1`` for
    tests so the worker doesn't interfere with asyncio event loops.
    """
    global _EMBED_WORKER
    if _EMBED_WORKER is not None:
        return _EMBED_WORKER
    import os as _os
    if _os.environ.get("NEXUS_DISABLE_EMBED_WORKER"):
        return None
    with _EMBED_WORKER_LOCK:
        if _EMBED_WORKER is not None:
            return _EMBED_WORKER
        try:
            from ghidra_nexus.notebook.embed_worker import EmbedWorker
            from ghidra_nexus.notebook.embedder import get_embedder
        except ImportError:
            return None
        # Synchronous path: caller cannot await, but the worker itself uses a
        # background thread. We need the notebook synchronously.
        try:
            nb = _NOTEBOOK_SINGLETON or _try_open_default_notebook()
            if nb is None:
                return None
            worker = EmbedWorker(nb, get_embedder())
            worker.start()
            _EMBED_WORKER = worker
            return worker
        except Exception as e:
            logger.debug("embed worker init failed: %s", e)
            return None


def _try_open_default_notebook() -> Notebook | None:
    """Best-effort: open notebook at the default path."""
    try:
        return Notebook.open("ghidra_nexus_projects/my_project-nexus/notebook.sqlite")
    except Exception:
        return None


def _stop_embed_worker() -> None:
    """Stop the worker if running (called on daemon shutdown)."""
    global _EMBED_WORKER
    if _EMBED_WORKER is not None:
        try:
            _EMBED_WORKER.stop()
        except Exception:
            pass
        _EMBED_WORKER = None


def _get_binary_meta(
    pyghidra_context: MCPContext,
    binary_name: str,
    program_info,  # JVM-side ProgramInfo
) -> tuple[str, str | None, int]:
    """Return (sha256, image_base, generation) for the binary.

    ``generation`` is the analysis_generation from the notebook — 0 on first
    use, bumped by the binary's bump_generation method.

    Defensive: every attribute is validated to be ``str | None`` so a Mock or
    malformed object (common in unit tests) cannot poison the notebook cache
    with non-string values that fail SQLite type checking.
    """
    sha256: str = ""
    image_base: str | None = None
    try:
        from ghidra_nexus.context import PyGhidraContext

        val = PyGhidraContext._safe_sha256(program_info)
        if isinstance(val, str):
            sha256 = val
    except Exception:
        pass
    try:
        meta = getattr(program_info, "metadata", None)
        if isinstance(meta, dict):
            for key in ("Image Base", "image_base"):
                candidate = meta.get(key)
                if isinstance(candidate, str) and candidate:
                    image_base = candidate
                    break
    except Exception:
        pass
    return sha256, image_base, 0  # generation handled by notebook.binaries via bump_generation


def _error_tool_response(
    code: ToolErrorCode | str, message: str, **kwargs
) -> dict:
    """Build a tool-result dict that conforms to the ToolError schema."""
    return make_tool_error(code, message, **kwargs)


class _ToolRecoverable(Exception):  # noqa: N818 — historical name kept for compat
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
            ctx = kwargs.get("ctx")
            if ctx is None:
                return
            pyghidra_context = _get_context(ctx)
            nb = await _get_notebook(pyghidra_context)
            binary_name = kwargs.get("binary_name")
            bid = None
            if binary_name:
                b = nb.binaries.get(binary_name)
                if b:
                    bid = b["id"]
            record_breadcrumb(nb, binary_id=bid, session_id=_SESSION_ID, tool=tool_name,
                              summary=f"{action} on {binary_name}" if binary_name else action)
        except Exception:
            logger.debug("breadcrumb failed for %s", tool_name, exc_info=True)

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
    nb = await _get_notebook(pyghidra_context)
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


def _search_code_empty_guard(
    query: str,
    search_mode: str,
    b: dict | None,
    vec_available: bool,
    offset: int,
    limit: int,
) -> CodeSearchResults | None:
    """Return a refused-result if the query is empty on a large binary."""
    if query and query.strip():
        return None
    if not (b and b.get("binary_class") in {"large", "very_large"}):
        return None
    return CodeSearchResults(
        results=[],
        query=query,
        search_mode=SearchMode(search_mode if search_mode != "hybrid" else "semantic"),
        vec_available=vec_available,
        vec_index_complete=False,
        backend="fts_only",
        returned_count=0,
        offset=offset,
        limit=limit,
        total_functions=0,
        literal_total=0,
        semantic_total=0,
        reliability_notes=["empty query refused on large/very_large binary"],
    )


def _search_code_semantic_degrade(
    nb: "Notebook",
    query: str,
    binary_name: str,
    bid: int,
    search_mode: str,
    vec_available: bool,
    vec_index_complete: bool,
    offset: int,
    limit: int,
    preview_length: int,
) -> CodeSearchResults | None:
    """Handle semantic-mode unavailable / incomplete cases."""
    if search_mode != "semantic":
        return None
    if not vec_available:
        raise _ToolRecoverable(
            ToolErrorCode.SEMANTIC_BACKEND_UNAVAILABLE,
            f"sqlite-vec is not available; semantic search cannot run for '{binary_name}'.",
            binary_name=binary_name,
            fallback_tool="notebook_embed_status",
            hint=(
                "Check notebook_embed_status for the vec backend state, "
                "or use search_mode='hybrid'/'literal'."
            ),
        )
    if vec_index_complete:
        return None

    from ghidra_nexus.notebook.search import hybrid_search

    result = hybrid_search(
        nb.conn,
        query,
        None,
        binary_id=bid if bid else None,
        kind=None,
        limit=limit,
        offset=offset,
        vec_available=False,
    )
    hits = [
        CodeSearchResult(
            function_name=h.get("name", ""),
            code=h.get("snippet", "")[:preview_length],
            similarity=float(h.get("score", 0)),
            search_mode=SearchMode.LITERAL,
            preview=h.get("snippet", "")[:preview_length],
        )
        for h in result["results"]
    ]
    return CodeSearchResults(
        results=hits,
        query=query,
        search_mode=SearchMode.SEMANTIC,
        vec_available=True,
        vec_index_complete=False,
        backend="fts_only",
        returned_count=result["returned"],
        offset=offset,
        limit=limit,
        total_functions=result["total_fts"],
        literal_total=result["total_fts"],
        semantic_total=0,
        reliability_notes=[
            "semantic index is still building; returned FTS-only results. "
            "Call notebook_embed_status to check progress, or retry shortly."
        ],
    )


@mcp_error_handler
async def search_code(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 5,
    offset: int = 0,
    search_mode: Literal["semantic", "literal", "hybrid"] = "hybrid",
    include_full_code: bool = False,
    preview_length: int = 500,
    similarity_threshold: float = 0.0,
    min_quality: Literal["ok", "stub", "empty", "encrypted", "any"] = "any",
) -> CodeSearchResults:
    """Semantic / lexical search over the notebook knowledge plane.

    Default backend: notebook/sqlite-vec hybrid (FTS5 + vec KNN → RRF merge).
    Falls back to FTS-only when sqlite-vec is unavailable.
    Set env ``NEXUS_SEMANTIC_BACKEND=chromadb`` for the legacy ChromaDB path.

    Args:
        search_mode: ``hybrid`` (FTS + vec → RRF), ``literal`` (FTS only),
            ``semantic`` (vec KNN only).
        include_full_code: Default ``False`` — hit payloads carry summary preview
            only. Set ``True`` to also return the gzipped full decompile window
            for each hit (still subject to ``preview_length``).
        min_quality: Filter views whose ``quality_hint`` is below this threshold.
            ``any`` returns everything; ``ok`` hides stubs/empty/encrypted.
    """
    import os as _os

    if _os.environ.get("NEXUS_SEMANTIC_BACKEND") == "chromadb":
        _, program_info = _require_program(ctx, binary_name, require_analysis=True)
        tools = GhidraTools(program_info)
        def _legacy():
            return tools.search_code(query=query, limit=limit, offset=offset,
                search_mode=SearchMode(search_mode if search_mode != "hybrid" else "semantic"),
                include_full_code=include_full_code, preview_length=preview_length,
                similarity_threshold=similarity_threshold)
        return await get_executor().submit(program_info, _legacy, task_id=f"search_code:{binary_name}:{query[:40]}")

    pyghidra_context, _ = _require_program(ctx, binary_name, require_analysis=False)
    nb = await _get_notebook(pyghidra_context)
    b = nb.binaries.get(binary_name)
    bid = b["id"] if b else 0
    vec_available = nb.vec_available
    vec_index_complete = bool((b or {}).get("vec_index_complete", 0))

    empty_guard = _search_code_empty_guard(
        query, search_mode, b, vec_available, offset, limit
    )
    if empty_guard is not None:
        return empty_guard

    semantic_degrade = _search_code_semantic_degrade(
        nb, query, binary_name, bid, search_mode, vec_available, vec_index_complete,
        offset, limit, preview_length,
    )
    if semantic_degrade is not None:
        return semantic_degrade

    query_vec = None
    if vec_available and search_mode in ("semantic", "hybrid"):
        from ghidra_nexus.notebook.embedder import get_embedder
        embedder = get_embedder()
        query_vec = embedder.encode(query)

    # Phase 6.1: SLM query expansion. Opt-in via NEXUS_SLM_MODEL. The SLM
    # reformulates the natural-language query into FTS-friendly tokens +
    # related API names; we then run the FTS path with the expanded query
    # and the embedder path with the original query (so semantic recall is
    # preserved). Any failure / disabled state falls back to the raw query.
    fts_query_for_search = query
    if query and _os.environ.get("NEXUS_SLM_MODEL"):
        try:
            from ghidra_nexus.slm import is_available as _slm_available
            if _slm_available():
                from ghidra_nexus.slm import run_query_expand as _slm_qe
                # Build alias + api context (bounded, async-safe)
                _alias_names: list[str] = []
                for r in nb.conn.execute(
                    "SELECT name FROM aliases WHERE binary_id = ? AND name IS NOT NULL",
                    (bid,),
                ).fetchall():
                    if r[0]:
                        _alias_names.append(r[0])
                _known_apis: list[str] = []
                for r in nb.conn.execute(
                    "SELECT DISTINCT value FROM artifact_views, json_each(key_entities) "
                    "WHERE artifact_views.binary_id = ? "
                    "AND json_extract(value, '$.kind') = 'api' LIMIT 30",
                    (bid,),
                ).fetchall():
                    if r[0]:
                        _known_apis.append(r[0])
                _expanded = await asyncio.to_thread(
                    _slm_qe,
                    binary_name=binary_name,
                    query=query,
                    known_aliases=_alias_names,
                    known_apis=_known_apis,
                )
                if _expanded.fts_query:
                    fts_query_for_search = _expanded.fts_query
        except Exception as e:
            logger.debug("SLM query_expand failed; using raw query: %s", e)

    from ghidra_nexus.notebook.search import hybrid_search
    # We pass `query` (raw) to search_fts internally for the snippet match
    # and the expanded fts_query for the ranking signal. hybrid_search takes
    # the user-supplied query for snippet; the FTS MATCH is built from
    # the fts_query. See hybrid_search for the exact contract.
    result = hybrid_search(nb.conn, fts_query_for_search, query_vec, binary_id=bid if bid else None,
        kind=None, limit=limit, offset=offset,
        vec_available=vec_available and query_vec is not None)

    # Apply min_quality filter (post-filter; small result sets, <50ms typical)
    if min_quality != "any":
        result["results"] = _filter_by_quality(
            nb.conn, result["results"], min_quality
        )
        result["returned"] = len(result["results"])

    hits = []
    for h in result["results"]:
        preview = h.get("snippet", "")[:preview_length]
        if include_full_code:
            # Resolve the full decompile window from cache if requested
            full = _resolve_full_code(nb, h, preview_length)
            code_payload = full or preview
        else:
            code_payload = preview
        hits.append(CodeSearchResult(
            function_name=h.get("name", ""),
            code=code_payload,
            similarity=float(h.get("score", 0)),
            search_mode=SearchMode(search_mode if search_mode != "hybrid" else "semantic"),
            preview=preview,
        ))

    return CodeSearchResults(
        results=hits, query=query,
        search_mode=SearchMode(search_mode if search_mode != "hybrid" else "semantic"),
        vec_available=result["vec_available"],
        vec_index_complete=vec_index_complete,
        backend=result["backend"],
        returned_count=result["returned"],
        offset=offset, limit=limit,
        total_functions=result["total_fts"] + result["total_vec"],
        literal_total=result["total_fts"],
        semantic_total=result["total_vec"],
    )


def _filter_by_quality(
    conn: "sqlite3.Connection",
    hits: list[dict],
    min_quality: str,
) -> list[dict]:
    """Drop hits whose source artifact_view has quality_hint below ``min_quality``.

    Quality ordering: stub < empty < encrypted < ok.
    """
    quality_order = {"stub": 0, "empty": 1, "encrypted": 2, "ok": 3, "unknown": 1}
    threshold = quality_order.get(min_quality, 0)
    out = []
    for h in hits:
        rva = h.get("rva", "")
        kind = h.get("kind", "")
        binary_id = h.get("binary_id")
        if not rva or not binary_id:
            out.append(h)
            continue
        row = conn.execute(
            "SELECT quality_hint FROM artifact_views WHERE binary_id = ? AND rva = ? AND kind = ? ORDER BY id DESC LIMIT 1",
            (binary_id, rva, kind),
        ).fetchone()
        q = row[0] if row else "unknown"
        if quality_order.get(q, 0) >= threshold:
            out.append(h)
    return out


def _resolve_full_code(
    nb: "Notebook",
    hit: dict,
    preview_length: int,
) -> str | None:
    """Best-effort: pull the cached decompile blob for a hit and return a window.

    Returns None on miss so the caller can fall back to the preview snippet.
    """
    rva = hit.get("rva", "")
    binary_id = hit.get("binary_id")
    if not rva or not binary_id:
        return None
    try:
        cached = nb.decompiles.get(binary_id, rva)
    except Exception:
        return None
    if not cached:
        return None
    code = cached.get("code_text", "")
    if not code:
        return None
    from ghidra_nexus.notebook.pagination import window_text

    page = window_text(code, offset=0, limit=preview_length // 24)
    return page.text


@mcp_error_handler
async def list_project_binaries(ctx: Context) -> ProgramInfos:
    pyghidra_context = _get_context(ctx)
    programs = pyghidra_context.list_project_binary_infos()
    return ProgramInfos(programs=programs)


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

    nb = await _get_notebook(pyghidra_context)
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
    nb = await _get_notebook(pyghidra_context)
    sha256, image_base, _gen = _get_binary_meta(pyghidra_context, binary_name, program_info)
    bid = resolve_binary_id(nb, binary_name, sha256, image_base=image_base)

    # F1 hard gate: very_large binaries require a non-trivial query to avoid
    # unbounded string scans. Short/empty patterns are rejected with a fallback.
    b = nb.binaries.get(binary_name) if nb else None
    binary_class = (b or {}).get("binary_class", "unknown")
    is_very_large = isinstance(binary_class, str) and binary_class.startswith("very_large")
    query_stripped = query.strip() if isinstance(query, str) else ""
    if is_very_large and len(query_stripped) < 3:
        raise _ToolRecoverable(
            ToolErrorCode.INVALID_PARAMS,
            f"String scan on very_large binary '{binary_name}' requires a query of at least 3 characters.",
            binary_name=binary_name,
            fallback_tool="notebook_search",
            hint="Narrow the search with a longer substring, or use notebook_search over cached views.",
        )

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
    nb = await _get_notebook(pyghidra_context)
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
async def disassemble_call_site(
    binary_name: str,
    ctx: Context,
    function: str,
    offset: int = 0,
    limit: int = 0,
    max_scan: int = 40,
) -> CallSiteAnalysisResult:
    """Reconstruct stack-argument evidence for every CALL in a function.

    For each call site (direct or indirect), walks backwards from the CALL
    collecting PUSH / MOV [sp+X] writes with call-time stack offsets,
    resolves one level of register indirection (e.g. ``push edx`` after
    ``lea edx, [esp+14h]`` → ``&[sp+0xNN]``), reports ECX ``this`` evidence
    and post-call stack cleanup, and infers the calling convention with an
    explicit confidence level. Use this before porting any call to another
    language — decompiler pseudocode can hide a non-standard push order.
    """
    if max_scan <= 0 or max_scan > 500:
        raise _ToolRecoverable(
            ToolErrorCode.INVALID_RANGE,
            "max_scan must be in 1..500",
            binary_name=binary_name,
            addr=function,
        )
    limit = clamp_limit("call_sites", limit if limit > 0 else None)

    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)
    nb = await _get_notebook(pyghidra_context)
    sha256, image_base, _gen = _get_binary_meta(pyghidra_context, binary_name, program_info)
    bid = resolve_binary_id(nb, binary_name, sha256, image_base=image_base)
    rva = _resolve_rva(function, program_info)

    cached = check_callsite_cache(
        nb, binary_id=bid, rva=rva, current_gen=0, offset=offset, limit=limit
    )
    if cached is not None:
        return CallSiteAnalysisResult(binary_name=binary_name, **cached)

    tools = GhidraTools(program_info)

    def _run():
        return tools.analyze_call_sites(function, max_scan=max_scan, binary_name=binary_name)

    result = await get_executor().submit(
        program_info, _run, task_id=f"disassemble_call_site:{binary_name}:{function}"
    )

    site_dicts = [s.model_dump() for s in result.call_sites]
    write_callsite_cache(
        nb,
        binary_id=bid,
        binary_name=binary_name,
        rva=rva,
        current_gen=0,
        result={
            "function_name": result.function_name,
            "function_address": result.function_address,
            "call_sites": site_dicts,
            "total_call_sites": result.total_call_sites,
        },
    )

    window = window_list(site_dicts, offset=offset, limit=limit)
    items = window.pop("items")
    return CallSiteAnalysisResult(
        function_name=result.function_name,
        function_address=result.function_address,
        binary_name=binary_name,
        call_sites=[CallSiteInfo(**d) for d in items],
        total_call_sites=result.total_call_sites,
        page=window,
    )


@mcp_error_handler
async def verify_port(
    binary_name: str,
    ctx: Context,
    target: str,
    signature: str,
    call_site: str | None = None,
) -> VerifyPortResult:
    """Pre-flight check of a proposed ported signature against binary evidence.

    ``target`` is a function name or address; ``signature`` is the C-style
    prototype you intend to port to (e.g.
    ``"int __thiscall Lock(int flags, uint count, void **out, int arg2)"``).
    Compares calling convention, parameter count, and stack-parameter bytes
    (from ``ret N`` epilogues, or from call-site push evidence when
    ``call_site`` is given) and returns pass/fail per check. Read-only —
    parses but never applies the signature. Run this BEFORE writing hook
    bytes; it catches argument-order and cleanup-convention mismatches.
    """
    if not signature or not signature.strip():
        raise _ToolRecoverable(
            ToolErrorCode.INVALID_PARAMS,
            "signature must be a non-empty C-style prototype, "
            "e.g. 'int __thiscall Lock(int flags, uint count)'",
            binary_name=binary_name,
            addr=target,
        )
    pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)

    tools = GhidraTools(program_info)

    def _run():
        return tools.verify_port(
            target, signature, call_site=call_site, binary_name=binary_name
        )

    result = await get_executor().submit(
        program_info, _run, task_id=f"verify_port:{binary_name}:{target}"
    )

    # Knowledge plane: record the verdict and surface any prior one
    # (state-drift rule — return the diff, not just the latest answer).
    try:
        nb = await _get_notebook(pyghidra_context)
        sha256, image_base, _gen = _get_binary_meta(pyghidra_context, binary_name, program_info)
        bid = resolve_binary_id(nb, binary_name, sha256, image_base=image_base)
        rva = _resolve_rva(result.addr or target, program_info)

        prior_row = nb.port_verifications.latest_for(bid, rva)
        if prior_row is not None:
            result.prior_verdict = {
                "verdict": prior_row.get("verdict"),
                "signature": prior_row.get("signature"),
                "created_at": str(prior_row.get("created_at")),
            }
            prior_sig = prior_row.get("signature")
            if isinstance(prior_sig, str) and prior_sig and prior_sig != signature:
                result.warnings.append(
                    f"prior verification used a different signature: {prior_sig}"
                )

        nb.port_verifications.put(
            binary_id=bid,
            rva=rva,
            signature=signature,
            signature_hash=_signature_hash(signature),
            verdict=result.verdict,
            checks=[c.model_dump() for c in result.checks],
            warnings=result.warnings,
            call_site_rva=_resolve_rva(call_site, program_info) if call_site else None,
        )
    except Exception:
        logger.warning("verify_port: failed to record verdict", exc_info=True)

    return result


def _signature_hash(signature: str) -> str:
    normalized = " ".join(signature.split()).lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@mcp_error_handler
async def override_callsite_signature(
    binary_name: str,
    ctx: Context,
    function: str,
    call_site: str,
    signature: str,
) -> CallsiteOverrideResult:
    """Override the prototype used at ONE call site (write operation).

    The programmatic form of the decompiler's "Override Signature" action:
    Ghidra re-decompiles the containing function with ``signature`` applied
    at the call instruction at ``call_site``. Use after
    ``disassemble_call_site`` shows a non-standard convention and
    ``verify_port`` confirms the corrected one. The result's ``verified``
    flag confirms the override marker was read back from the program.
    """
    if not signature or not signature.strip():
        raise _ToolRecoverable(
            ToolErrorCode.INVALID_PARAMS,
            "signature must be a non-empty C-style prototype, "
            "e.g. 'int __thiscall Lock(void *this, int flags)'",
            binary_name=binary_name,
            addr=call_site,
        )
    _pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)

    tools = GhidraTools(program_info)

    def _run():
        return tools.override_callsite_signature(
            function, call_site, signature, binary_name=binary_name
        )

    return await get_executor().submit(
        program_info,
        _run,
        write=True,
        task_id=f"override_callsite_signature:{binary_name}:{call_site}",
    )


@mcp_error_handler
async def generate_hook_stub(
    binary_name: str,
    ctx: Context,
    target: str,
    language: str = "zig",
    call_site: str | None = None,
) -> HookStubResult:
    """Generate a Zig/C hook stub from call-site or function evidence.

    ``target`` is a function name or address. With ``call_site`` set, the
    stub is built from that call's stack evidence (push order, slot
    offsets, ECX `this`, register clobbers); without it, from the
    function's declared prototype. Types from call-site evidence are
    pointer-vs-word guesses — run ``verify_port`` first and refine types
    against the decompilation. Read-only.
    """
    _pyghidra_context, program_info = _require_program(ctx, binary_name, require_analysis=True)

    tools = GhidraTools(program_info)

    def _run():
        return tools.generate_hook_stub(
            target, language=language, call_site=call_site, binary_name=binary_name
        )

    return await get_executor().submit(
        program_info, _run, task_id=f"generate_hook_stub:{binary_name}:{target}"
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


def _resolve_live_program_info(pyghidra_context, name: str):
    """Return the live ProgramInfo for ``name`` if it is currently open."""
    try:
        with getattr(pyghidra_context, "_programs_lock", threading.Lock()):
            programs = getattr(pyghidra_context, "programs", {}) or {}
            return programs.get(name)
    except Exception:
        return None


def _resolve_function_count(raw, live_pi, pyghidra_context) -> int:
    """Prefer live function count, fall back to raw/metadata."""
    from ghidra_nexus.context import PyGhidraContext

    count = int(getattr(raw, "function_count", 0) or 0)
    if isinstance(raw.metadata, dict) and not count:
        count = int(raw.metadata.get("function_count") or 0)
    if live_pi is not None:
        try:
            count = PyGhidraContext._safe_function_count(live_pi) or count
        except Exception:
            pass
    return count


def _resolve_sha256(raw, live_pi) -> str | None:
    """Prefer live sha256, fall back to raw/metadata."""
    from ghidra_nexus.context import PyGhidraContext

    sha256 = getattr(raw, "sha256", None)
    if isinstance(raw.metadata, dict) and not sha256:
        sha256 = raw.metadata.get("sha256")
    if live_pi is not None:
        try:
            sha256 = PyGhidraContext._safe_sha256(live_pi) or sha256
        except Exception:
            pass
    return sha256


def _resolve_entropy_summary(raw, live_pi, pyghidra_context) -> str:
    """Prefer live entropy summary, fall back to raw/metadata."""
    entropy_summary = getattr(raw, "entropy_summary", None) or "unknown"
    if isinstance(raw.metadata, dict) and entropy_summary in (None, "unknown", "normal"):
        entropy_summary = raw.metadata.get("entropy_summary") or entropy_summary
    if live_pi is None:
        return entropy_summary or "unknown"

    ensure = getattr(pyghidra_context, "ensure_entropy_summary", None)
    if callable(ensure):
        try:
            return ensure(live_pi) or entropy_summary or "unknown"
        except Exception:
            pass
    if getattr(live_pi, "entropy_summary", None):
        return live_pi.entropy_summary
    return entropy_summary or "unknown"


def _compute_state_and_recommendations(raw, function_count: int) -> tuple[str, list[str]]:
    """Return (analysis_state, recommended_tools) from raw status + live count."""
    if raw.analysis_complete:
        state = "complete"
        if function_count == 0:
            recommended = ["section_health", "survey_binary_fast"]
        elif getattr(raw, "code_indexed", False):
            recommended = ["survey_binary_full", "search_code"]
        else:
            recommended = ["section_health", "survey_binary_full"]
    else:
        state = getattr(raw, "analysis_state", None) or "analyzing_functions"
        recommended = ["survey_binary_fast", "section_health", "analysis_status"]
    return state, recommended


def _path_exists(file_path: str | None) -> bool | None:
    """Best-effort check whether ``file_path`` exists on disk."""
    if not file_path:
        return None
    try:
        return Path(file_path).exists()
    except Exception:
        return None


def _notebook_counts(nb, bid: int | None) -> dict[str, int]:
    """Return cache counters from the notebook for ``bid``."""
    counts = {
        "cached_decompiles": 0,
        "cached_disassemblies": 0,
        "artifact_views": 0,
        "embedded_count": 0,
    }
    if bid is None or nb is None:
        return counts
    try:
        counts["cached_decompiles"] = nb.decompiles.count_for_binary(bid)
        counts["cached_disassemblies"] = nb.disassemblies.count_for_binary(bid)
        counts["artifact_views"] = nb.views.count_for_binary(bid)
        counts["embedded_count"] = nb.embeddings.count_for_binary(bid)
    except Exception:
        pass
    return counts


@mcp_error_handler
def _build_program_info(
    raw,
    *,
    pyghidra_context,
    nb,
    project_path_str: str | None,
    nexus_dir_str: str | None,
) -> ProgramInfo:
    """Build a single enriched ProgramInfo from Ghidra + notebook state."""
    vec_data = nb.binaries.get(raw.name) if nb else {}
    bid = vec_data.get("id") if vec_data else None

    live_pi = _resolve_live_program_info(pyghidra_context, raw.name)
    function_count = _resolve_function_count(raw, live_pi, pyghidra_context)
    sha256 = _resolve_sha256(raw, live_pi)
    entropy_summary = _resolve_entropy_summary(raw, live_pi, pyghidra_context)
    state, recommended = _compute_state_and_recommendations(raw, function_count)
    path_exists = _path_exists(raw.file_path)
    counts = _notebook_counts(nb, bid)

    return ProgramInfo(
        name=raw.name,
        file_path=raw.file_path,
        load_time=raw.load_time,
        analysis_complete=raw.analysis_complete,
        metadata=raw.metadata if isinstance(raw.metadata, dict) else {},
        code_indexed=raw.code_indexed,
        strings_indexed=raw.strings_indexed,
        analysis_state=state,
        function_count=function_count,
        sha256=sha256,
        entropy_summary=entropy_summary,
        project_path=project_path_str,
        nexus_data_dir=nexus_dir_str,
        idb_path=raw.file_path,
        path_exists=path_exists,
        recommended_tools=recommended,
        vec_available=nb.vec_available if nb else False,
        vec_status=vec_data.get("vec_status", "unavailable") if vec_data else "unavailable",
        vec_index_complete=bool(vec_data.get("vec_index_complete", 0)) if vec_data else False,
        embed_progress=vec_data.get("embed_progress", 0) if vec_data else 0,
        embed_target=vec_data.get("embed_target", 0) if vec_data else 0,
        embed_model=vec_data.get("embed_model") if vec_data else None,
        binary_class=vec_data.get("binary_class", "unknown") if vec_data else "unknown",
        analysis_ready=bool(vec_data.get("analysis_ready", 0)) if vec_data else False,
        cached_decompiles=counts["cached_decompiles"],
        cached_disassemblies=counts["cached_disassemblies"],
        artifact_views=counts["artifact_views"],
        embedded_count=counts["embedded_count"],
    )


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
        - ``binary_class`` / ``analysis_ready`` — notebook capability envelope (F1)
        - ``cached_decompiles`` / ``cached_disassemblies`` / ``artifact_views`` /
          ``embedded_count`` — notebook cache state
        - ``vec_status`` / ``vec_available`` / ``vec_index_complete`` /
          ``embed_progress`` / ``embed_target`` / ``embed_model`` — semantic
          readiness
        - ``project_path`` / ``nexus_data_dir`` / ``idb_path`` — absolute paths
          the agent can validate against ``os.path.exists``
        - ``recommended_tools`` — what to call next given current state

    Server-level:
        - ``path_warnings`` — writability warnings about the project path. Empty
          on a healthy setup; surfaces UAC-locked directories on Windows before
          project writes silently fail.
    """
    from ghidra_nexus import __version__
    from ghidra_nexus.server import _check_project_path_writable

    pyghidra_context = _get_context(ctx)
    raw_infos = pyghidra_context.list_project_binary_infos()
    nb = await _get_notebook(pyghidra_context)

    project_path_str = str(getattr(pyghidra_context, "project_path", None) or "") or None
    nexus_dir_str = str(getattr(pyghidra_context, "nexus_data_dir", None) or "") or None

    binaries = [
        _build_program_info(
            raw,
            pyghidra_context=pyghidra_context,
            nb=nb,
            project_path_str=project_path_str,
            nexus_dir_str=nexus_dir_str,
        )
        for raw in raw_infos
    ]

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
    nb = await _get_notebook(pyghidra_context)
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


# ---- notebook_* tools (Phase 3) ----


@mcp_error_handler
async def notebook_summary(binary_name: str | None, ctx: Context) -> dict:
    """Per-binary aggregate stats from the notebook cache."""
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise _ToolRecoverable(ToolErrorCode.BINARY_NOT_FOUND, f"Binary {binary_name!r} not in notebook", binary_name=binary_name)
        return {
            "binary_name": b["name"], "sha256": b["sha256"], "binary_class": b["binary_class"],
            "function_count": b["function_count"], "analysis_ready": bool(b["analysis_ready"]),
            "cached_decompiles": nb.decompiles.count_for_binary(b["id"]),
            "cached_disassemblies": nb.disassemblies.count_for_binary(b["id"]),
            "artifact_views": nb.views.count_for_binary(b["id"]),
            "aliases": len(nb.aliases.list(b["id"])),
            "breadcrumbs_24h": len(nb.breadcrumbs.recent(limit=9999)),
            "vec_available": nb.vec_available,
            "vec_index_complete": bool(b.get("vec_index_complete", 0)),
            "embed_progress": b.get("embed_progress", 0),
            "embed_target": b.get("embed_target", 0),
            "reliability_notes": b.get("reliability_notes"),
        }
    all_bins = nb.binaries.all()
    return {"binaries": [{"name": b["name"], "class": b["binary_class"], "function_count": b["function_count"]} for b in all_bins]}


@mcp_error_handler
async def notebook_search(binary_name: str, query: str, ctx: Context, kind: str = "any", limit: int = 20, offset: int = 0) -> dict:
    """FTS5 search over notebook views (summary + entities + function names)."""
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    b = nb.binaries.get(binary_name)
    bid = b["id"] if b else 0
    hits = nb.search.query(query, binary_id=bid if bid else None, kind=None if kind == "any" else kind, limit=limit, offset=offset)
    return {"hits": hits, "query": query, "kind": kind, "returned": len(hits), "limit": limit, "offset": offset}


@mcp_error_handler
async def notebook_breadcrumbs(binary_name: str | None, ctx: Context, session_id: str | None = None, limit: int = 50) -> list[dict]:
    """Recent tool-call breadcrumbs from the notebook audit trail."""
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    bid = None
    if binary_name:
        b = nb.binaries.get(binary_name)
        if b:
            bid = b["id"]
    sid = session_id or _SESSION_ID
    return nb.breadcrumbs.recent(binary_id=bid, session_id=sid, limit=limit)


@mcp_error_handler
async def notebook_alias(binary_name: str, addr: str, ctx: Context, name: str | None = None, tags: list[str] | None = None, status: str | None = None, notes: str | None = None) -> dict:
    """Set or get an address alias."""
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    b = nb.binaries.get(binary_name)
    if not b:
        raise _ToolRecoverable(ToolErrorCode.BINARY_NOT_FOUND, f"Binary {binary_name!r} not found", binary_name=binary_name)
    if name is None and tags is None:
        a = nb.aliases.get(b["id"], addr)
        return a if a else {"addr": addr, "name": None, "tags": [], "status": "unknown"}
    nb.aliases.upsert(binary_id=b["id"], rva=addr, name=name or "", tags=tags, status=status, notes=notes)
    a = nb.aliases.get(b["id"], addr)
    return a if a else {}


@mcp_error_handler
async def notebook_hypothesis(action: str, ctx: Context, id: int | None = None, binary_name: str | None = None, text: str | None = None, status: str | None = None) -> dict:
    """Hypothesis board CRUD (create, update, list, get)."""
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    bid = None
    if binary_name:
        b = nb.binaries.get(binary_name)
        if b:
            bid = b["id"]
    if action == "create":
        hid = nb.hypotheses.create(text=text or "", binary_id=bid, status=status or "open")
        return nb.hypotheses.get(hid) or {"id": hid}
    elif action == "update" and id is not None:
        nb.hypotheses.update(id, status=status or "open", **({"text": text} if text else {}))
        return nb.hypotheses.get(id) or {}
    elif action == "list":
        return {"hypotheses": nb.hypotheses.list(binary_id=bid, status=status)}
    elif action == "get" and id is not None:
        return nb.hypotheses.get(id) or {}
    raise _ToolRecoverable(ToolErrorCode.INVALID_PARAMS, f"Unknown action {action!r} or missing id")


@mcp_error_handler
async def notebook_embed_status(ctx: Context, binary_name: str | None = None) -> dict:
    """Inspect the embed queue + vec index status.

    Returns aggregate counters (pending/done/error/skipped) for the queue and
    per-binary vec readiness. If ``binary_name`` is given, narrows to that
    binary. ``None`` returns project-wide rollup.

    The ``embed_worker`` running flag reflects whether a background drainer
    is attached to this notebook. If false, the queue accumulates but the
    worker is idle (e.g. vec unavailable or embedder failed to load).
    """
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    worker = _get_embed_worker()
    # Queue counters via raw SQL (single round-trip)
    queue_counts = {
        r[0]: int(r[1])
        for r in nb.conn.execute(
            "SELECT status, COUNT(*) FROM embed_queue GROUP BY status"
        ).fetchall()
    }
    for k in ("pending", "done", "error", "skipped"):
        queue_counts.setdefault(k, 0)

    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise _ToolRecoverable(
                ToolErrorCode.BINARY_NOT_FOUND,
                f"Binary {binary_name!r} not in notebook",
                binary_name=binary_name,
            )
        bid = b["id"]
        binary_summary = {
            "name": b["name"],
            "binary_class": b["binary_class"],
            "vec_available": nb.vec_available,
            "vec_status": b.get("vec_status", "unavailable"),
            "vec_index_complete": bool(b.get("vec_index_complete", 0)),
            "embed_progress": b.get("embed_progress", 0),
            "embed_target": b.get("embed_target", 0),
            "embed_model": b.get("embed_model"),
            "views_count": nb.views.count_for_binary(bid),
            "embeddings_count": nb.embeddings.count_for_binary(bid),
        }
        return {
            "embed_worker_running": worker.running if worker else False,
            "embed_worker_errors": worker._total_errors if worker else 0,
            "embed_worker_processed": worker._total_processed if worker else 0,
            "queue_counts": queue_counts,
            "binary": binary_summary,
        }

    # Project-wide rollup
    binaries = nb.binaries.all()
    return {
        "embed_worker_running": worker.running if worker else False,
        "embed_worker_errors": worker._total_errors if worker else 0,
        "embed_worker_processed": worker._total_processed if worker else 0,
        "queue_counts": queue_counts,
        "binaries": [
            {
                "name": b["name"],
                "binary_class": b["binary_class"],
                "vec_status": b.get("vec_status", "unavailable"),
                "vec_index_complete": bool(b.get("vec_index_complete", 0)),
                "embed_progress": b.get("embed_progress", 0),
                "embed_target": b.get("embed_target", 0),
                "views_count": nb.views.count_for_binary(b["id"]),
                "embeddings_count": nb.embeddings.count_for_binary(b["id"]),
            }
            for b in binaries
        ],
    }


@mcp_error_handler
async def notebook_query_expand(
    ctx: Context,
    binary_name: str,
    query: str,
) -> dict:
    """Reformulate a natural-language search query into FTS-friendly tokens.

    **Phase 6.1 (SLM tools).** Opt-in via ``NEXUS_SLM_MODEL`` env var. When
    the SLM is not configured, returns ``slm_disabled`` with a fallback
    to ``search_code`` (raw query). When configured, the SLM produces
    grounded tokens + related API names + a reformulated ``fts_query`` that
    is fed into the existing ``search_code`` FTS path.

    Grounded output: every token is a valid lowercase identifier; every
    API name is checked against a built-in catalog (~150 common Windows /
    POSIX APIs); the fts_query has balanced quotes and an alphanumeric
    token. Grounding failures fall back to a heuristic expansion
    (whitespace-split lowercase).

    Env vars: ``NEXUS_SLM_MODEL`` (e.g. ``Qwen/Qwen2.5-Coder-1.5B-Instruct``),
    ``NEXUS_SLM_DEVICE`` (cpu/cuda/mps), ``NEXUS_SLM_TIMEOUT_SEC`` (default 30).
    """
    from ghidra_nexus.slm import (
        is_available as _slm_available,
        run_query_expand as _slm_run_query_expand,
    )

    if not _slm_available():
        return {
            "ok": False,
            "error_code": "slm_disabled",
            "message": (
                "NEXUS_SLM_MODEL is not set. Pass NEXUS_SLM_MODEL=<hf_id> to "
                "enable SLM-backed query expansion. The raw query is still "
                "usable via search_code (search_mode='hybrid')."
            ),
            "fallback_tool": "search_code",
        }

    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    b = nb.binaries.get(binary_name)
    if not b:
        raise _ToolRecoverable(
            ToolErrorCode.BINARY_NOT_FOUND,
            f"Binary {binary_name!r} not in notebook",
            binary_name=binary_name,
        )
    bid = b["id"]

    # Pull existing alias names and API references from the notebook to
    # give the SLM context. Bounded to keep the prompt short.
    alias_names: list[str] = []
    for row in nb.conn.execute(
        "SELECT name FROM aliases WHERE binary_id = ? AND name IS NOT NULL",
        (bid,),
    ).fetchall():
        if row[0]:
            alias_names.append(row[0])
    known_apis: list[str] = []
    for row in nb.conn.execute(
        "SELECT DISTINCT value FROM artifact_views, json_each(key_entities) "
        "WHERE artifact_views.binary_id = ? "
        "AND json_extract(value, '$.kind') = 'api' LIMIT 30",
        (bid,),
    ).fetchall():
        if row[0]:
            known_apis.append(row[0])

    try:
        result = await asyncio.to_thread(
            _slm_run_query_expand,
            binary_name=binary_name,
            query=query,
            known_aliases=alias_names,
            known_apis=known_apis,
        )
    except Exception as e:
        logger.debug("SLM query_expand failed: %s", e, exc_info=True)
        return {
            "ok": False,
            "error_code": "slm_failed",
            "message": f"SLM query expansion failed; falling back to search_code. ({e})",
            "fallback_tool": "search_code",
        }

    return {
        "ok": True,
        "raw_query": result.raw_query,
        "tokens": result.tokens,
        "related_apis": result.related_apis,
        "fts_query": result.fts_query,
        "rationale": result.rationale,
        "model": result.model,
        "latency_ms": result.latency_ms,
    }


@mcp_error_handler
async def notebook_rebuild_embeddings(
    ctx: Context,
    binary_name: str | None = None,
) -> dict:
    """Rebuild the sqlite-vec index from scratch.

    Behavior:
      - If ``binary_name`` is given: delete that binary's embeddings + vec0
        rows, mark its vec_index_complete=False, then enqueue every view for
        re-embedding. The worker (if running) drains the queue automatically.
      - If ``binary_name`` is None: rebuild for ALL binaries in the project.

    Use this when ``search_code`` shows ``vec_index_complete=false`` but
    ``embed_progress >= embed_target`` (stuck) or after a model upgrade.
    """
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    if not nb.vec_available:
        raise _ToolRecoverable(
            ToolErrorCode.SEMANTIC_BACKEND_UNAVAILABLE,
            "sqlite-vec not loaded; cannot rebuild embeddings. Install `sqlite-vec` or set SQLITE_VEC_PATH.",
        )

    targets: list[tuple[int, str]] = []
    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise _ToolRecoverable(
                ToolErrorCode.BINARY_NOT_FOUND,
                f"Binary {binary_name!r} not in notebook",
                binary_name=binary_name,
            )
        targets.append((b["id"], b["name"]))
    else:
        for b in nb.binaries.all():
            targets.append((b["id"], b["name"]))

    total_views_requeued = 0
    for bid, name in targets:
        # Drop embeddings meta + vec0 rows for this binary
        nb.embeddings.delete_for_binary(bid)
        try:
            from ghidra_nexus.notebook.vec import delete_vecs_for_binary
            delete_vecs_for_binary(nb.conn, bid)
        except Exception:
            pass
        # Reset binary vec status
        nb.binaries.set_vec_status(
            name, vec_available=nb.vec_available, model=None,
            index_complete=False, progress=0, target=0,
        )
        # Re-enqueue every view
        for view in nb.conn.execute(
            "SELECT id FROM artifact_views WHERE binary_id = ?", (bid,)
        ).fetchall():
            vid = int(view[0])
            nb.embed_queue.enqueue(vid)
            total_views_requeued += 1

    # Bump the worker (lazy start if not running)
    _get_embed_worker()
    return {
        "rebuild_started": True,
        "binaries_affected": [name for _, name in targets],
        "views_requeued": total_views_requeued,
        "hint": "call notebook_embed_status to monitor progress",
    }


@mcp_error_handler
async def notebook_archive_breadcrumbs(
    ctx: Context,
    binary_name: str | None = None,
    session_id: str | None = None,
    age_days: int = 30,
) -> dict:
    """Archive (and delete) breadcrumbs older than ``age_days``.

    The archive table preserves audit history; the hot ``breadcrumbs`` table
    stays small. If ``binary_name`` is given, only crumbs for that binary are
    archived. If ``session_id`` is given, only that session is targeted.
    """
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    bid = None
    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise _ToolRecoverable(
                ToolErrorCode.BINARY_NOT_FOUND,
                f"Binary {binary_name!r} not in notebook",
                binary_name=binary_name,
            )
        bid = b["id"]

    result = nb.breadcrumbs.archive_old(
        binary_id=bid, session_id=session_id, age_days=max(1, age_days)
    )
    return {
        "archived": result["archived"],
        "deleted": result["deleted"],
        "age_days": max(1, age_days),
        "binary_name": binary_name,
        "session_id": session_id,
    }


@mcp_error_handler
async def notebook_vacuum(
    ctx: Context,
    binary_name: str | None = None,
    keep_generations: int = 2,
    run_vacuum: bool = False,
) -> dict:
    """Reclaim notebook space by deleting stale cache generations.

    Keeps the newest ``keep_generations`` of decompiles, disassemblies, and
    call-site analyses per binary. Set ``run_vacuum=True`` to run SQLite
    ``VACUUM`` afterward, which rewires the DB file and requires temporary
    disk space (~2x the file size).
    """
    pyghidra_context = _get_context(ctx)
    nb = await _get_notebook(pyghidra_context)
    if keep_generations < 1:
        raise _ToolRecoverable(
            ToolErrorCode.INVALID_PARAMS,
            "keep_generations must be >= 1",
        )

    targets: list[tuple[int, str]] = []
    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise _ToolRecoverable(
                ToolErrorCode.BINARY_NOT_FOUND,
                f"Binary {binary_name!r} not in notebook",
                binary_name=binary_name,
            )
        targets.append((b["id"], b["name"]))
    else:
        for b in nb.binaries.all():
            targets.append((b["id"], b["name"]))

    total_decompiles = 0
    total_disassemblies = 0
    total_call_sites = 0
    for bid, _name in targets:
        total_decompiles += nb.decompiles.delete_old_generations(bid, keep_generations)
        total_disassemblies += nb.disassemblies.delete_old_generations(bid, keep_generations)
        total_call_sites += nb.call_sites.delete_old_generations(bid, keep_generations)

    freed_note = "VACUUM not run; set run_vacuum=True to reclaim file space."
    if run_vacuum:
        try:
            nb.conn.execute("VACUUM")
            freed_note = "VACUUM completed successfully."
        except Exception as e:
            freed_note = f"VACUUM failed: {e}"

    return {
        "binaries_affected": [name for _, name in targets],
        "decompiles_deleted": total_decompiles,
        "disassemblies_deleted": total_disassemblies,
        "call_sites_deleted": total_call_sites,
        "keep_generations": keep_generations,
        "vacuum_note": freed_note,
    }


@mcp_error_handler
async def save(ctx: Context) -> SaveRequestResult:
    pyghidra_context = _get_context(ctx)
    pyghidra_context.save()
    return SaveRequestResult()


# ---- Lazy activation tools (for streamable-http daemon mode) ----

_AWAKE = False
_AWAKE_LOCK = threading.Lock()


def _register_lazy_tools(mcp_server):
    """Register only the wake/status tools (streamable-http daemon cold start).

    The daemon starts without the JVM; the agent calls ``wake_ghidra`` to boot
    Ghidra, which then registers the full analysis surface via
    :func:`_register_all_on_demand`.
    """
    for fn, name in ((wake_ghidra, "wake_ghidra"), (ghidra_status, "ghidra_status")):
        try:
            mcp_server.add_tool(fn, name=name)
        except Exception:
            logger.warning("Failed to register tool %s", name, exc_info=True)


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
        (disassemble_call_site, "disassemble_call_site"),
        (verify_port, "verify_port"),
        (override_callsite_signature, "override_callsite_signature"),
        (generate_hook_stub, "generate_hook_stub"),
        (gen_callgraph, "gen_callgraph"),
        (section_health, "section_health"),
        (analysis_status, "analysis_status"),
        (import_binary, "import_binary"),
        (save, "save"),
        (notebook_summary, "notebook_summary"),
        (notebook_search, "notebook_search"),
        (notebook_breadcrumbs, "notebook_breadcrumbs"),
        (notebook_alias, "notebook_alias"),
        (notebook_hypothesis, "notebook_hypothesis"),
        (notebook_embed_status, "notebook_embed_status"),
        (notebook_rebuild_embeddings, "notebook_rebuild_embeddings"),
        (notebook_archive_breadcrumbs, "notebook_archive_breadcrumbs"),
        (notebook_vacuum, "notebook_vacuum"),
        (notebook_query_expand, "notebook_query_expand"),
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
