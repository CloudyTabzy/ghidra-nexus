"""Notebook cache (Phase 2) — check-hit → write-through → extract → view → FTS → embed_queue.

Every read-heavy MCP tool calls into this module. On cache miss, after Ghidra returns
a result, the handler calls the ``write_*`` companion which:
  1. Stores the gzipped full blob in the raw table (decompiles / disassemblies / etc.)
  2. Runs the registered schema-aware extractor → :class:`ExtractedView`
  3. Upserts the view into ``artifact_views``
  4. Indexes the view via FTS5
  5. Enqueues the view for embedding (stub — Phase 3 processes)

None of this code touches the JVM — Ghidra calls happen in the MCP handler via
the executor. This module's reads are pure SQLite (<1ms). Writes are serialised
through the Notebook's ``transaction()`` context.

Design principle F11: extractors + views are NOT optional. Every cache put must
produce a view. If extraction fails, we still store the raw blob (raw is SSOT)
and log a warning — never fail the tool call.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

from ghidra_nexus.notebook.addresses import to_int, to_rva
from ghidra_nexus.notebook.extractors import extract_for
from ghidra_nexus.notebook.pagination import window_text

if TYPE_CHECKING:
    from ghidra_nexus.context import ProgramInfo as JvmProgramInfo
    from ghidra_nexus.notebook.store import Notebook

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Registry: resolve binary → (id, image_base, generation)
# ---------------------------------------------------------------------------

def resolve_binary_id(
    nb: Notebook,
    binary_name: str,
    sha256: str,
    *,
    image_base: str | None = None,
    arch: str | None = None,
) -> int:
    """Return ``binary_id``, upserting the row if needed."""
    b = nb.binaries.get(binary_name)
    if b is not None:
        return b["id"]
    return nb.binaries.upsert(
        name=binary_name,
        sha256=sha256,
        image_base=image_base,
        arch=arch,
    )


def _get_image_base(program_info: JvmProgramInfo) -> str | None:
    """Best-effort image_base from the Ghidra program metadata.

    Defensive: any non-dict metadata or non-string image_base is treated as
    "no base" rather than passed downstream (where it would crash SQLite
    binding or ``to_int``).
    """
    try:
        meta = getattr(program_info, "metadata", {}) or {}
        if not isinstance(meta, dict):
            return None
        for key in ("image_base", "Image Base"):
            val = meta.get(key)
            if isinstance(val, str) and val:
                return val
    except Exception:
        pass
    return None


def _get_function_count(program_info: JvmProgramInfo) -> int | None:
    try:
        import ghidra_nexus.context as _ctx

        return _ctx.PyGhidraContext._safe_function_count(program_info)
    except Exception:
        return None


def _source_hash(binary_sha256: str, rva: str, generation: int) -> str:
    """Deterministic hash of the source state that produced a decompile."""
    return hashlib.sha256(f"{binary_sha256}:{rva}:{generation}".encode()).hexdigest()


def _resolve_rva(addr: str, program_info: JvmProgramInfo) -> str:
    """Convert an agent-supplied address (or symbol name) to canonical RVA.

    Symbol names (e.g. ``"main"``) cannot be converted to an RVA at the cache
    layer — return the symbol as-is so the cache miss flows through to Ghidra,
    which resolves the symbol via its name table.
    """
    image_base = _get_image_base(program_info)
    if image_base is None:
        # No base — try to normalize; if it's a symbol name, pass it through.
        from ghidra_nexus.notebook.addresses import normalize_hex

        try:
            return normalize_hex(addr)
        except ValueError:
            return addr
    try:
        n = to_int(addr)
    except ValueError:
        # Not a hex address — must be a symbol name.
        return addr
    base = to_int(image_base) if image_base else 0
    if n >= base and base > 0:
        return to_rva(addr, image_base)
    from ghidra_nexus.notebook.addresses import normalize_hex

    return normalize_hex(addr)


# ---------------------------------------------------------------------------
# Decompile cache
# ---------------------------------------------------------------------------

def check_decompile_cache(
    nb: Notebook,
    *,
    binary_id: int,
    rva: str,
    current_gen: int,
    offset: int,
    limit: int,
) -> dict | None:
    """Return a dict suitable for the MCP response if cached, or None."""
    cached = nb.decompiles.get(binary_id, rva)
    if cached is None:
        return None
    # Stale check: if the binary was re-analyzed and the stored generation
    # is older, invalidate.
    stored_gen = cached.get("analysis_generation", 0)
    if stored_gen < current_gen:
        logger.debug("decompile cache stale: %s/%s gen=%d < current=%d", binary_id, rva, stored_gen, current_gen)
        return None
    window = window_text(cached.get("code_text", ""), offset=offset, limit=limit)
    return {
        "cached": True,
        "lines": cached.get("lines", 0),
        "decompiler_status": "decompiled",
        "code": window.text,  # only the window to keep the existing contract
        "page": window.as_dict(),
    }


def write_decompile_cache(
    nb: Notebook,
    *,
    binary_id: int,
    binary_name: str,
    binary_sha256: str,
    rva: str,
    current_gen: int,
    result: dict,  # dict with "code", "lines", "signature", "error_code", etc.
) -> None:
    """Store full decompile blob + run extractor + view + FTS + embed."""
    code = result.get("code") or ""
    lines = result.get("lines") or (code.count("\n") + 1 if code else 0)
    source_hash = _source_hash(binary_sha256, rva, current_gen)
    try:
        row_id = nb.decompiles.put(
            binary_id=binary_id,
            rva=rva,
            code=code,
            lines=lines,
            source_hash=source_hash,
            warnings=result.get("warnings"),
            analysis_generation=current_gen,
        )

        name = result.get("name") or ""
        # Run extractor (best-effort — never fail the tool call)
        payload = {
            "name": name,
            "rva": rva,
            "code": code,
            "lines": lines,
            "signature": result.get("signature"),
            "decompiler_status": result.get("decompiler_status", "decompiled"),
            "error_code": result.get("error_code"),
        }
        view = extract_for("decompile", payload)
        if view is not None:
            vid = nb.views.upsert(
                binary_id=binary_id,
                rva=rva,
                kind="decompile",
                source_table="decompiles",
                source_row_id=row_id,
                summary=view.summary,
                key_entities=view.entities_json(),
                view_model=view.view_model,
                analysis_generation=current_gen,
            )
            nb.search.upsert(
                kind="decompile",
                binary_id=binary_id,
                rva=rva,
                name=name,
                body=view.search_blob(),
            )
            nb.embed_queue.enqueue(vid)
    except Exception:
        logger.warning("write_decompile_cache failed for %s/%s", binary_name, rva, exc_info=True)


# ---------------------------------------------------------------------------
# Disassembly cache
# ---------------------------------------------------------------------------

def check_disasm_cache(
    nb: Notebook,
    *,
    binary_id: int,
    rva: str,
    current_gen: int,
    offset: int,
    limit: int,
) -> dict | None:
    cached = nb.disassemblies.get(binary_id, rva)
    if cached is None:
        return None
    stored_gen = cached.get("analysis_generation", 0)
    if stored_gen < current_gen:
        return None
    window = window_text(cached.get("asm_text", ""), offset=offset, limit=limit)
    return {
        "cached": True,
        "listing": window.text,
        "count": window.returned_lines,
        "page": window.as_dict(),
    }


def write_disasm_cache(
    nb: Notebook,
    *,
    binary_id: int,
    binary_name: str,
    rva: str,
    current_gen: int,
    result: dict,
) -> None:
    listing = result.get("listing") or ""
    count = result.get("count") or result.get("instruction_count") or listing.count("\n") + (1 if listing else 0)
    try:
        row_id = nb.disassemblies.put(
            binary_id=binary_id,
            rva=rva,
            asm=listing,
            instruction_count=count,
            analysis_generation=current_gen,
        )
        payload = {
            "name": result.get("function_name") or "",
            "address": result.get("address") or "",
            "listing": listing,
            "count": count,
        }
        view = extract_for("disasm", payload)
        if view is not None:
            vid = nb.views.upsert(
                binary_id=binary_id,
                rva=rva,
                kind="disasm",
                source_table="disassemblies",
                source_row_id=row_id,
                summary=view.summary,
                key_entities=view.entities_json(),
                view_model=view.view_model,
                analysis_generation=current_gen,
            )
            nb.search.upsert(kind="disasm", binary_id=binary_id, rva=rva, name=payload["name"], body=view.search_blob())
            nb.embed_queue.enqueue(vid)
    except Exception:
        logger.warning("write_disasm_cache failed for %s/%s", binary_name, rva, exc_info=True)


# ---------------------------------------------------------------------------
# Xrefs cache
# ---------------------------------------------------------------------------

def check_xrefs_cache(
    nb: Notebook,
    *,
    binary_id: int,
    rva: str,
    offset: int,
    limit: int,
) -> dict | None:
    # Xrefs are typically bulk-replaced; check if any row exists.
    count = nb.xrefs.count_to(binary_id, rva)
    if count == 0:
        return None
    window = nb.xrefs.list_to(binary_id, rva, offset=offset, limit=limit)
    window["cached"] = True
    return window


def write_xrefs_cache(
    nb: Notebook,
    *,
    binary_id: int,
    binary_name: str,
    rva: str,
    current_gen: int,
    result: dict,
) -> None:
    xrefs = result.get("cross_references") or []
    from_rva = rva
    try:
        if xrefs:
            refs = [
                {
                    "from_rva": x.get("from_address", from_rva),
                    "to_rva": x.get("to_address", ""),
                    "xref_type": x.get("type", "code"),
                    "call_site": x.get("from_address"),
                }
                for x in xrefs
            ]
            nb.xrefs.bulk_replace_for_target(binary_id, rva, refs)
        payload = {
            "target": rva,
            "cross_references": xrefs,
        }
        view = extract_for("xrefs", payload)
        if view is not None:
            vid = nb.views.upsert(
                binary_id=binary_id,
                rva=rva,
                kind="xrefs",
                source_table="xrefs",
                summary=view.summary,
                key_entities=view.entities_json(),
                view_model=view.view_model,
                analysis_generation=current_gen,
            )
            nb.search.upsert(kind="xrefs", binary_id=binary_id, rva=rva, name="", body=view.search_blob())
            nb.embed_queue.enqueue(vid)
    except Exception:
        logger.warning("write_xrefs_cache failed for %s/%s", binary_name, rva, exc_info=True)


# ---------------------------------------------------------------------------
# Strings cache
# ---------------------------------------------------------------------------

def check_strings_cache(
    nb: Notebook,
    *,
    binary_id: int,
    pattern: str,
    offset: int,
    limit: int,
) -> dict | None:
    window = nb.strings.search_like(binary_id, pattern, offset=offset, limit=limit)
    if window["total"] == 0:
        return None
    window["cached"] = True
    return window


def write_strings_cache(
    nb: Notebook,
    *,
    binary_id: int,
    binary_name: str,
    current_gen: int,
    result: dict,
) -> None:
    strings = result.get("strings") or []
    try:
        if strings:
            nb.strings.bulk_upsert(binary_id, [
                {"rva": s.get("address") or s.get("rva") or "", "text": s.get("value", ""),
                 "encoding": s.get("encoding", "ascii")}
                for s in strings
            ])
        payload = {"strings": strings}
        view = extract_for("strings", payload)
        if view is not None:
            vid = nb.views.upsert(
                binary_id=binary_id,
                rva="",
                kind="strings",
                source_table="strings",
                summary=view.summary,
                key_entities=view.entities_json(),
                view_model=view.view_model,
                analysis_generation=current_gen,
            )
            nb.search.upsert(kind="strings", binary_id=binary_id, rva="", name="", body=view.search_blob())
            nb.embed_queue.enqueue(vid)
    except Exception:
        logger.warning("write_strings_cache failed for %s", binary_name, exc_info=True)


# ---------------------------------------------------------------------------
# Breadcrumb insert
# ---------------------------------------------------------------------------


def record_breadcrumb(
    nb: Notebook,
    *,
    binary_id: int | None,
    session_id: str,
    tool: str,
    args_hash: str | None = None,
    summary: str = "",
    rva: str | None = None,
    duration_ms: int | None = None,
    truncated: bool = False,
    error_code: str | None = None,
) -> None:
    """Insert a breadcrumb row (best-effort; never raises)."""
    try:
        nb.breadcrumbs.insert(
            binary_id=binary_id,
            session_id=session_id,
            tool=tool,
            args_hash=args_hash,
            summary=summary,
            rva=rva,
            duration_ms=duration_ms,
            truncated=1 if truncated else 0,
            error_code=error_code,
        )
    except Exception:
        logger.debug("breadcrumb insert failed for %s", tool, exc_info=True)
