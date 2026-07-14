"""Hybrid search (Phase 3) — FTS5 + sqlite-vec knn → RRF merge.

The default ``search_code`` backend. When sqlite-vec is available, runs the query
through both FTS5 (lexical) and vec KNN (semantic) and merges results via
reciprocal rank fusion. When vec is unavailable, degrades to FTS-only.

Search targets: artifact_views (summary + entities), embeddings (semantic), and
function names (high-value for symbol-driven lookups).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    import sqlite3


logger = logging.getLogger(__name__)


RRF_K = 60


def _rrf_key(kind: str, binary_id: int, rva: str) -> str:
    return f"{kind}:{binary_id}:{rva}"


def rrf_merge(
    fts_hits: list[dict],
    vec_hits: list[dict],
    *,
    k: int = RRF_K,
    exclude_kind: str | None = None,
) -> list[dict]:
    """Merge FTS and vec hit lists by reciprocal rank fusion.

    Each hit dict must carry keys ``kind``, ``binary_id``, ``rva``, and ``score``.
    Hits whose ``kind`` matches ``exclude_kind`` are dropped (used to filter
    low-quality or stub entries).
    """
    scores: dict[str, float] = {}
    meta: dict[str, dict] = {}

    for rank, h in enumerate(fts_hits):
        if exclude_kind and h.get("kind") == exclude_kind:
            continue
        key = _rrf_key(h["kind"], h["binary_id"], h["rva"])
        score = 1.0 / (k + rank + 1)
        scores[key] = scores.get(key, 0.0) + score
        meta.setdefault(key, h)

    for rank, h in enumerate(vec_hits):
        if exclude_kind and h.get("kind") == exclude_kind:
            continue
        key = _rrf_key(h["kind"], h["binary_id"], h["rva"])
        score = 1.0 / (k + rank + 1)
        scores[key] = scores.get(key, 0.0) + score
        meta.setdefault(key, {**h, "source": h.get("source", "vec")})

    sorted_keys = sorted(scores, key=lambda k: scores[k], reverse=True)
    return [
        {
            **meta[key],
            "rrf_score": scores[key],
            "source": "hybrid" if key in {
                _rrf_key(h["kind"], h["binary_id"], h["rva"]) for h in fts_hits
            } and key in {
                _rrf_key(h["kind"], h["binary_id"], h["rva"]) for h in vec_hits
            } else meta[key].get("source", "fts"),
        }
        for key in sorted_keys
    ]


def search_fts(
    conn: "sqlite3.Connection",
    query: str,
    *,
    binary_id: int | None = None,
    kind: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Run an FTS5 query and return hits enriched with view metadata."""
    from ghidra_nexus.notebook.pagination import clamp_limit, validate_offset

    limit = clamp_limit("fts", limit)
    offset = validate_offset("fts", offset)

    safe = query.replace('"', '""')
    if any(c in safe for c in "*():?~"):
        safe = f'"{safe}"'

    params: list = [safe]
    sql = (
        "SELECT kind, binary_id, rva, name, snippet(fts, 3, '<b>', '</b>', '...', 32) AS snippet, rank "
        "FROM fts WHERE fts MATCH ?"
    )
    if binary_id is not None:
        sql += " AND binary_id = ?"
        params.append(binary_id)
    if kind is not None:
        sql += " AND kind = ?"
        params.append(kind)
    sql += " ORDER BY rank LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(sql, params).fetchall()
    return [
        {
            "kind": r[0],
            "binary_id": r[1],
            "rva": r[2],
            "name": r[3],
            "snippet": r[4],
            "score": float(r[5]),
            "source": "fts",
        }
        for r in rows
    ]


def search_vec(
    conn: "sqlite3.Connection",
    query_vec: np.ndarray,
    *,
    binary_id: int | None = None,
    limit: int = 20,
    threshold: float = 999.0,
) -> list[dict]:
    """Run KNN over vec_embeddings, returning hits linked to artifact_views."""
    from ghidra_nexus.notebook.vec import EMBED_DIM, knn_query

    knn_results = knn_query(conn, query_vec=query_vec, k=limit * 3, dim=EMBED_DIM)
    if not knn_results:
        return []

    rowids: list[int] = [r[0] for r in knn_results]
    distances: dict[int, float] = {r[0]: r[1] for r in knn_results}

    placeholders = ",".join("?" for _ in rowids)
    sql = f"""SELECT e.id, e.binary_id, e.rva, e.kind, av.summary,
                     av.summary AS snippet, e.analysis_generation
              FROM embeddings e
              LEFT JOIN artifact_views av ON av.id = e.src_view_id
              WHERE e.id IN ({placeholders})"""
    params = list(rowids)
    if binary_id is not None:
        sql += " AND e.binary_id = ?"
        params.append(binary_id)

    rows = conn.execute(sql, params).fetchall()

    results = []
    for r in rows:
        dist = distances.get(r[0], 999.0)
        if dist > threshold:
            continue
        results.append({
            "kind": r[3] or "unknown",
            "binary_id": r[1],
            "rva": r[2] or "",
            "name": "",
            "snippet": (r[4] or r[5] or "")[:500],
            "score": float(dist),
            "source": "vec",
        })

    results.sort(key=lambda x: x["score"])
    return results[:limit]


def hybrid_search(
    conn: "sqlite3.Connection",
    query: str,
    query_vec: np.ndarray | None,
    *,
    binary_id: int | None = None,
    kind: str | None = None,
    limit: int = 20,
    offset: int = 0,
    vec_available: bool = False,
) -> dict:
    """Run hybrid search (FTS + optional vec → RRF).

    Returns a dict with the standard pagination envelope + backend info.
    """
    fts_hits = search_fts(conn, query, binary_id=binary_id, kind=kind, limit=limit * 2, offset=0)

    vec_hits = []
    if vec_available and query_vec is not None:
        vec_hits = search_vec(conn, query_vec, binary_id=binary_id, limit=limit * 2)

    if vec_hits:
        merged = rrf_merge(fts_hits, vec_hits, exclude_kind="stub")
        backend = "hybrid"
    else:
        merged = fts_hits
        backend = "fts_only"

    # Apply offset/limit to merged results
    page = merged[offset : offset + limit]

    return {
        "results": page,
        "query": query,
        "backend": backend,
        "vec_available": vec_available,
        "offset": offset,
        "limit": limit,
        "returned": len(page),
        "total_fts": len(fts_hits),
        "total_vec": len(vec_hits),
    }
