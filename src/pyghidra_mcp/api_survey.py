"""Binary survey tool — complete triage in one call (Ghidra adaptation).

Adapted from Synapse MCP's api_survey.py to use Ghidra's APIs. Returns a
single comprehensive snapshot of a binary: file metadata, segment layout,
entry points, statistics, top strings/functions by xref count, imports by
category, and a call-graph summary.

Concurrency: every function in this module performs pure reads against a
Ghidra ``Program``. Callers must invoke ``survey_binary`` from inside the
``GhidraExecutor`` background thread (per the project's single-JVM funnel
rule), so this module does not lock or schedule anything itself.
"""

from __future__ import annotations

import hashlib
import re
from collections import deque

from pyghidra_mcp.models import (
    SurveyCallGraphSummary,
    SurveyEntrypoint,
    SurveyImportEntry,
    SurveyImportsByCategory,
    SurveyInterestingFunction,
    SurveyInterestingString,
    SurveyMetadata,
    SurveyRecommendedTools,
    SurveySegmentInfo,
    SurveyStatistics,
)

# ---------------------------------------------------------------------------
# Caps — same as Synapse to keep behaviour predictable across tools.
# ---------------------------------------------------------------------------

# Max functions to iterate for xref counting on large binaries.
_MAX_FUNC_ITER = 10_000

# Max strings to process when ranking by xref count (perf cap).
_MAX_STRING_ITER = 5_000

# Max xrefs to materialise per string when counting.
_MAX_XREFS_PER_STRING = 200

# Top-N entries returned for ranking lists.
_TOP_N = 15

# BFS visit cap for call-graph depth estimate.
_MAX_BFS_VISITS = 50_000


# ---------------------------------------------------------------------------
# Import categorisation — keep the same regex table as Synapse so a Ghidra
# binary's import profile lines up with what a reverse engineer would expect
# from a Synapse session.
# ---------------------------------------------------------------------------

_IMPORT_CATEGORIES: list[tuple[str, re.Pattern[str]]] = [
    (
        "crypto",
        re.compile(r"crypt|aes|sha[^r]|md5|hash|rsa|\bssl\b|\btls\b|\bcert", re.IGNORECASE),
    ),
    (
        "network",
        re.compile(r"socket|connect|send|recv|http|url|internet|ws2|winsock", re.IGNORECASE),
    ),
    (
        "process",
        re.compile(r"process|thread|terminate|execute|shell|pipe|virtual", re.IGNORECASE),
    ),
    (
        "registry",
        re.compile(r"reg|registry|hkey", re.IGNORECASE),
    ),
    (
        "file_io",
        re.compile(
            r"file|path|directory|fopen|fclose|fread|fwrite|readfile|writefile"
            r"|deletefile|createfile",
            re.IGNORECASE,
        ),
    ),
]


def _classify_import(name: str) -> str:
    """Return the first matching category for ``name`` (else ``"other"``)."""
    for category, pattern in _IMPORT_CATEGORIES:
        if pattern.search(name):
            return category
    return "other"


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_metadata(program) -> SurveyMetadata:
    """Path / module / arch / base / size / md5 / sha256 of the binary."""
    exe_path = ""
    try:
        exe_path = program.getExecutablePath() or ""
    except Exception:
        exe_path = ""

    # Ghidra's program name (short identifier, e.g. "find.exe").
    try:
        module = program.getName() or ""
    except Exception:
        module = ""

    # Architecture: derive "32" or "64" from the default pointer size.
    try:
        ptr_size = program.getDefaultPointerSize()
    except Exception:
        ptr_size = 0
    arch = "64" if ptr_size == 8 else ("32" if ptr_size == 4 else "unknown")

    base = "0x0"
    size = "0x0"
    try:
        base = hex(program.getImageBase().getOffset())
    except Exception:
        pass

    # Image size: sum of all memory blocks (initialised + uninitialised).
    try:
        total = 0
        for block in program.getMemory().getBlocks():
            try:
                total += int(block.getSize())
            except Exception:
                continue
        size = hex(total)
    except Exception:
        pass

    md5 = "unavailable"
    sha256 = "unavailable"
    if exe_path:
        try:
            with open(exe_path, "rb") as f:
                data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
        except Exception:
            md5 = sha256 = "unavailable"

    return SurveyMetadata(
        path=exe_path,
        module=module,
        arch=arch,
        base_address=base,
        image_size=size,
        md5=md5,
        sha256=sha256,
    )


def _build_segments(program) -> list[SurveySegmentInfo]:
    """Memory blocks formatted as rwx segment records."""
    segments: list[SurveySegmentInfo] = []
    try:
        blocks = list(program.getMemory().getBlocks())
    except Exception:
        return segments

    for block in blocks:
        try:
            name = block.getName() or ""
            start = block.getStart()
            end = block.getEnd()
            size = block.getSize()
            try:
                is_r = bool(block.isRead())
            except Exception:
                is_r = False
            try:
                is_w = bool(block.isWrite())
            except Exception:
                is_w = False
            try:
                is_x = bool(block.isExecute())
            except Exception:
                is_x = False
            perms = ("r" if is_r else "-") + ("w" if is_w else "-") + ("x" if is_x else "-")
            segments.append(
                SurveySegmentInfo(
                    name=name,
                    start=str(start),
                    end=str(end),
                    size=hex(int(size)),
                    permissions=perms,
                )
            )
        except Exception:
            # One bad block should not sink the whole survey.
            continue
    return segments


def _build_entrypoints(program) -> list[SurveyEntrypoint]:
    """External entry points declared by the binary."""
    entrypoints: list[SurveyEntrypoint] = []
    try:
        st = program.getSymbolTable()
    except Exception:
        return entrypoints

    # Map address -> name for quick lookup.
    addr_to_name: dict[str, str] = {}
    try:
        for sym in st.getExternalSymbols():
            try:
                addr_to_name[str(sym.getAddress())] = sym.getName() or ""
            except Exception:
                continue
    except Exception:
        pass

    try:
        it = st.getExternalEntryPointIterator()
    except Exception:
        return entrypoints

    seen: set[str] = set()
    try:
        while it.hasNext():
            addr = it.next()
            if addr is None:
                continue
            key = str(addr)
            if key in seen:
                continue
            seen.add(key)
            entrypoints.append(
                SurveyEntrypoint(
                    addr=key,
                    name=addr_to_name.get(key, ""),
                )
            )
    except Exception:
        pass
    return entrypoints


def _classify_function_kind(func) -> str:
    """Return one of: ``thunk``, ``library``, ``external``, ``named``, ``unnamed``."""
    try:
        if func.isThunk():
            return "thunk"
    except Exception:
        pass
    try:
        if func.isLibrary():
            return "library"
    except Exception:
        pass
    try:
        if func.isExternal():
            return "external"
    except Exception:
        pass
    try:
        name = func.getName() or ""
    except Exception:
        name = ""
    return "unnamed" if _looks_unnamed(name) else "named"


def _build_statistics(
    funcs: list, string_count: int, segment_count: int
) -> SurveyStatistics:
    """Count named / library / unnamed / thunk functions."""
    counts = {
        "thunk": 0,
        "library": 0,
        "external": 0,
        "named": 0,
        "unnamed": 0,
    }
    for func in funcs:
        if func is None:
            continue
        counts[_classify_function_kind(func)] += 1

    total = counts["thunk"] + counts["library"] + counts["named"] + counts["unnamed"]
    return SurveyStatistics(
        total_functions=total,
        named_functions=counts["named"],
        library_functions=counts["library"],
        unnamed_functions=counts["unnamed"],
        thunk_functions=counts["thunk"],
        total_strings=string_count,
        total_segments=segment_count,
    )


# Ghidra's default auto-generated names start with one of these prefixes.
_UNNAMED_PREFIXES = ("FUN_", "thunk_FUN_", "sub_", "LAB_", "loc_", "DAT_", "UNK_")


def _looks_unnamed(name: str) -> bool:
    if not name:
        return True
    return any(name.startswith(p) for p in _UNNAMED_PREFIXES)


# ---------------------------------------------------------------------------
# Interesting strings / functions
# ---------------------------------------------------------------------------


def _build_interesting_strings(program, max_strings: int) -> list[SurveyInterestingString]:
    """Top-15 defined strings ranked by incoming xref count."""
    rm = program.getReferenceManager()
    scored: list[tuple[int, str, str]] = []

    try:
        from ghidra.program.util import DefinedStringIterator

        try:
            it = DefinedStringIterator.forProgram(program)
        except Exception:
            it = DefinedStringIterator.definedStrings(program)
    except Exception:
        return []

    seen = 0
    for data in it:
        if seen >= max_strings:
            break
        try:
            s = str(data.getValue())
            addr = str(data.getAddress())
        except Exception:
            continue
        # Count incoming xrefs; cap to avoid pathological runtimes.
        try:
            count = 0
            for _ in rm.getReferencesTo(data.getAddress()):
                count += 1
                if count >= _MAX_XREFS_PER_STRING:
                    break
        except Exception:
            count = 0
        if count == 0:
            seen += 1
            continue
        scored.append((count, addr, s))
        seen += 1

    scored.sort(key=lambda t: t[0], reverse=True)
    return [
        SurveyInterestingString(addr=addr, string=s, xref_count=c)
        for c, addr, s in scored[:_TOP_N]
    ]


def _is_call_to_other(ref, self_func, fm) -> bool:
    """True when ``ref`` is a CALL-type reference to a function other than ``self_func``."""
    if ref is None:
        return False
    try:
        if not ref.getReferenceType().isCall():
            return False
    except Exception:
        return False
    try:
        target = fm.getFunctionContaining(ref.getToAddress())
    except Exception:
        return False
    return target is not None and target != self_func


def _count_call_callees(program, func) -> int:
    """Count outgoing CALL-type references from a function's body."""
    if func is None:
        return 0
    try:
        body = func.getBody()
    except Exception:
        return 0
    if body is None:
        return 0

    listing = program.getListing()
    fm = program.getFunctionManager()
    try:
        instrs = listing.getInstructions(body, True)
    except Exception:
        return 0

    count = 0
    for insn in instrs:
        try:
            refs = insn.getReferencesFrom()
        except Exception:
            continue
        for ref in refs:
            if _is_call_to_other(ref, func, fm):
                count += 1
    return count


def _classify_func(func, callee_count: int, size: int) -> str:
    """Thunk / wrapper / leaf / dispatcher / complex."""
    try:
        is_thunk = bool(func.isThunk())
    except Exception:
        is_thunk = False
    if is_thunk or size <= 8:
        return "thunk"
    if callee_count == 1 and size < 100:
        return "wrapper"
    if callee_count == 0:
        return "leaf"
    if callee_count > 10:
        return "dispatcher"
    return "complex"


def _is_user_defined_function(func) -> bool:
    """True when ``func`` should be considered for the interesting-functions list."""
    try:
        if func.isLibrary() or func.isExternal():
            return False
    except Exception:
        return False
    return True


def _function_summary(program, func) -> tuple[int, str, int] | None:
    """Return ``(xref_count, name, size)`` for ``func`` or ``None`` on failure."""
    try:
        name = func.getName() or ""
    except Exception:
        name = ""
    try:
        body = func.getBody()
    except Exception:
        body = None
    size = int(body.getNumAddresses()) if body is not None else 0
    try:
        entry = func.getEntryPoint()
    except Exception:
        return None
    rm = program.getReferenceManager()
    try:
        xref_count = sum(1 for _ in rm.getReferencesTo(entry))
    except Exception:
        xref_count = 0
    return xref_count, name, size


def _build_interesting_functions(
    program, func_iter, truncated: bool
) -> list[SurveyInterestingFunction]:
    """Top-15 non-library functions ranked by incoming xref count."""
    candidates: list[tuple[int, object, str, int]] = []
    for func in func_iter:
        if func is None or not _is_user_defined_function(func):
            continue
        summary = _function_summary(program, func)
        if summary is None:
            continue
        xref_count, name, size = summary
        candidates.append((xref_count, func, name, size))

    candidates.sort(key=lambda t: t[0], reverse=True)
    top = candidates[:_TOP_N]

    out: list[SurveyInterestingFunction] = []
    for xref_count, func, name, size in top:
        try:
            callees = _count_call_callees(program, func)
        except Exception:
            callees = 0
        try:
            addr = str(func.getEntryPoint())
        except Exception:
            addr = "0x0"
        classification = _classify_func(func, callees, size)
        out.append(
            SurveyInterestingFunction(
                addr=addr,
                name=name,
                size=size,
                xref_count=xref_count,
                callee_count=callees,
                type=classification,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Imports by category
# ---------------------------------------------------------------------------


def _build_imports_by_category(program) -> SurveyImportsByCategory:
    """Group all external symbols into the five Synapse categories + other."""
    cats: dict[str, list[SurveyImportEntry]] = {
        "crypto": [],
        "network": [],
        "file_io": [],
        "process": [],
        "registry": [],
        "other": [],
    }
    try:
        st = program.getSymbolTable()
    except Exception:
        return SurveyImportsByCategory(**cats)

    try:
        symbols = list(st.getExternalSymbols())
    except Exception:
        symbols = []

    for sym in symbols:
        try:
            name = sym.getName() or ""
            if not name:
                continue
            parent = sym.getParentNamespace()
            lib = parent.getName() if parent is not None else ""
            try:
                addr = str(sym.getAddress())
            except Exception:
                addr = ""
            cat = _classify_import(name)
            cats[cat].append(SurveyImportEntry(addr=addr, name=name, library=lib))
        except Exception:
            continue
    return SurveyImportsByCategory(**cats)


# ---------------------------------------------------------------------------
# Call-graph summary
# ---------------------------------------------------------------------------


def _function_entry_offset(func) -> int | None:
    """Return the integer offset of ``func``'s entry point, or ``None`` on failure."""
    try:
        return int(func.getEntryPoint().getOffset())
    except Exception:
        return None


def _function_instructions(program, func):
    """Yield instructions in ``func``'s body, or an empty iterator on failure."""
    if func is None:
        return
    try:
        body = func.getBody()
    except Exception:
        return
    if body is None:
        return
    listing = program.getListing()
    try:
        instrs = listing.getInstructions(body, True)
    except Exception:
        return
    yield from instrs


def _collect_call_edges(
    program, funcs: list, func_set: set[int]
) -> tuple[dict[int, set[int]], set[int], set[int], int]:
    """Walk every function and collect call edges as an adjacency map.

    Returns (adj, has_incoming, has_outgoing, total_edges). Targets that
    resolve outside ``func_set`` are skipped — they are external imports
    that don't contribute to the internal call graph.
    """
    fm = program.getFunctionManager()
    adj: dict[int, set[int]] = {ep: set() for ep in func_set}
    has_incoming: set[int] = set()
    has_outgoing: set[int] = set()
    total_edges = 0

    for func in funcs:
        ep = _function_entry_offset(func)
        if ep is None:
            continue
        for insn in _function_instructions(program, func):
            try:
                refs = insn.getReferencesFrom()
            except Exception:
                continue
            for ref in refs:
                tgt_ep = _resolve_internal_call_target(ref, fm, func_set)
                if tgt_ep is None:
                    continue
                adj[ep].add(tgt_ep)
                has_outgoing.add(ep)
                has_incoming.add(tgt_ep)
                total_edges += 1
    return adj, has_incoming, has_outgoing, total_edges


def _resolve_internal_call_target(ref, fm, func_set: set[int]) -> int | None:
    """If ``ref`` is a call inside ``func_set``, return the target entry offset."""
    if not _ref_is_internal_call(ref, fm, func_set):
        return None
    try:
        return int(
            fm.getFunctionContaining(ref.getToAddress())
            .getEntryPoint()
            .getOffset()
        )
    except Exception:
        return None


def _ref_is_internal_call(ref, fm, func_set: set[int]) -> bool:
    """True when ``ref`` is a CALL to a function inside ``func_set``."""
    if ref is None:
        return False
    try:
        if not ref.getReferenceType().isCall():
            return False
    except Exception:
        return False
    try:
        target = fm.getFunctionContaining(ref.getToAddress())
    except Exception:
        return False
    if target is None:
        return False
    try:
        return int(target.getEntryPoint().getOffset()) in func_set
    except Exception:
        return False


def _bfs_max_depth(adj: dict[int, set[int]], roots: list[int]) -> int | None:
    """Multi-source BFS that returns the deepest level reached, or None on failure."""
    try:
        visited: set[int] = set()
        depth: dict[int, int] = {ep: 0 for ep in roots}
        queue: deque[tuple[int, int]] = deque((ep, 0) for ep in roots)
        max_d = 0

        while queue:
            node, d = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            if len(visited) > _MAX_BFS_VISITS:
                break
            for neighbor in adj.get(node, ()):
                if neighbor in visited:
                    continue
                nd = d + 1
                existing = depth.get(neighbor)
                if existing is None or nd < existing:
                    depth[neighbor] = nd
                queue.append((neighbor, nd))
                if nd > max_d:
                    max_d = nd
        return max_d
    except Exception:
        return None


def _build_call_graph_summary(program, funcs: list) -> SurveyCallGraphSummary:
    """Approximate BFS depth + root/leaf counts for the call graph."""
    func_by_entry: dict[int, object] = {}
    func_set: set[int] = set()
    for func in funcs:
        if func is None:
            continue
        try:
            ep = int(func.getEntryPoint().getOffset())
        except Exception:
            continue
        func_by_entry[ep] = func
        func_set.add(ep)

    if not func_set:
        return SurveyCallGraphSummary(
            total_edges=0,
            max_depth_estimate=None,
            root_functions=[],
            leaf_functions_count=0,
        )

    adj, has_incoming, has_outgoing, total_edges = _collect_call_edges(
        program, funcs, func_set
    )

    root_funcs: list[str] = []
    leaf_count = 0
    for ep, func in func_by_entry.items():
        if ep not in has_incoming:
            try:
                root_funcs.append(func.getName() or hex(ep))
            except Exception:
                root_funcs.append(hex(ep))
        if ep not in has_outgoing:
            leaf_count += 1

    roots = [ep for ep in func_set if ep not in has_incoming]
    max_depth: int | None = _bfs_max_depth(adj, roots)

    return SurveyCallGraphSummary(
        total_edges=total_edges,
        max_depth_estimate=max_depth,
        root_functions=root_funcs[:100],
        leaf_functions_count=leaf_count,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def _recommended_tools() -> SurveyRecommendedTools:
    return SurveyRecommendedTools(
        interesting_strings=(
            "Use search_strings(query='...') for a full string-table scan, "
            "or list_xrefs on a string address to see every function that references it."
        ),
        interesting_functions=(
            "Use decompile_function(binary_name, name_or_address) for full decompilation, "
            "or disassemble for the assembly listing."
        ),
        imports_by_category=(
            "Use list_xrefs on a suspicious import address to find every caller, "
            "or decompile_function to inspect how the import is used."
        ),
        call_graph_summary=(
            "Use gen_callgraph(binary_name, function_name) for a per-function call graph, "
            "or decompile_function on a root function to trace program flow."
        ),
        overall=(
            "Start with decompile_function on a top interesting function, then trace data flow "
            "via list_xrefs and gen_callgraph. Use search_code for semantic queries."
        ),
    )


def survey_binary(program, *, detail_level: str = "standard") -> dict:
    """Build a single-call triage snapshot of ``program``.

    Parameters
    ----------
    program
        An open Ghidra ``Program`` (caller is responsible for ensuring the
        program has finished auto-analysis).
    detail_level
        ``"standard"`` returns the full payload (interesting_strings,
        interesting_functions, imports_by_category, call_graph_summary).
        ``"minimal"`` returns only metadata, statistics, segments, and
        entrypoints — use for very large binaries where the full payload
        would block the executor thread.

    Returns
    -------
    dict
        A plain ``dict`` mirroring ``SurveyBinaryResult`` so the caller
        (the MCP handler) can validate it through the Pydantic model.
    """
    minimal = detail_level == "minimal"

    # Collect all functions once, capping for large binaries.
    fm = program.getFunctionManager()
    try:
        all_funcs = list(fm.getFunctions(True))
    except Exception:
        all_funcs = []
    truncated = len(all_funcs) > _MAX_FUNC_ITER

    # Strings — DefinedStringIterator handles all the type-aware logic.
    try:
        from ghidra.program.util import DefinedStringIterator

        try:
            it = DefinedStringIterator.forProgram(program)
        except Exception:
            it = DefinedStringIterator.definedStrings(program)
        string_count = sum(1 for _ in it)
    except Exception:
        string_count = 0

    segments = _build_segments(program)
    metadata = _build_metadata(program)
    entrypoints = _build_entrypoints(program)
    statistics = _build_statistics(all_funcs, string_count, len(segments))

    result: dict = {
        "ok": True,
        "metadata": metadata,
        "statistics": statistics,
        "segments": segments,
        "entrypoints": entrypoints,
    }

    if not minimal:
        result["interesting_strings"] = _build_interesting_strings(
            program, _MAX_STRING_ITER
        )
        result["interesting_functions"] = _build_interesting_functions(
            program, all_funcs, truncated
        )
        result["imports_by_category"] = _build_imports_by_category(program)
        result["call_graph_summary"] = _build_call_graph_summary(program, all_funcs)

    result["recommended_tools"] = _recommended_tools()
    if truncated:
        result["note"] = (
            f"Binary has {len(all_funcs)} functions; interesting-function and "
            f"call-graph analysis was limited to the first {_MAX_FUNC_ITER} "
            f"for performance. Re-run with detail_level='minimal' for a faster "
            f"survey of huge binaries."
        )
    return result
