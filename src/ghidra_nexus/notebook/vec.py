"""sqlite-vec load, status, KNN query, and vector insert (F12).

Phase 3 extends Phase 1's soft-load probe with:
  - ``ensure_vec0_table``: create the vec0 virtual table once
  - ``insert_vec``: store a float32 vector
  - ``knn_query``: cosine-distance nearest neighbours
  - ``delete_binary_vecs``: remove vectors for a binary (rebuild)
"""

from __future__ import annotations

import logging
import os
import sqlite3
import struct
from dataclasses import dataclass
from typing import Final

import numpy as np


logger = logging.getLogger(__name__)


EMBED_MODEL_ID: Final[str] = "all-MiniLM-L6-v2"
EMBED_DIM: Final[int] = 384

# vec0 virtual table name (lives in the same SQLite file as the rest of the notebook)
VEC0_TABLE: Final[str] = "vec_embeddings"


@dataclass(frozen=True)
class VecStatus:
    """Outcome of :func:`try_enable_vec`."""

    available: bool
    error: str | None = None
    dim: int = EMBED_DIM
    model_default: str = EMBED_MODEL_ID


# ---- Phase 1 load probe (unchanged) ----

def try_enable_vec(conn: sqlite3.Connection) -> VecStatus:
    """Attempt to load sqlite-vec on ``conn``. Never raises."""
    # Strategy 1: bundled wheel loader
    try:
        import sqlite_vec  # type: ignore
        try:
            conn.enable_load_extension(True)
        except Exception:
            pass
        sqlite_vec.load(conn)
        if _vec0_works(conn):
            return VecStatus(available=True)
        return VecStatus(available=False, error="sqlite_vec loaded but vec0 unusable")
    except ImportError:
        pass
    except Exception as e:
        logger.debug("sqlite_vec.load failed: %s", e)

    # Strategy 2: SQLITE_VEC_PATH override
    vec_path = os.environ.get("SQLITE_VEC_PATH")
    if vec_path:
        try:
            conn.enable_load_extension(True)
            conn.load_extension(vec_path)
            if _vec0_works(conn):
                return VecStatus(available=True)
        except Exception as e:
            logger.debug("SQLITE_VEC_PATH load failed: %s", e)

    msg = (
        "sqlite-vec not available. Hybrid search disabled; FTS-only mode. "
        "Install with `uv add sqlite-vec` or set SQLITE_VEC_PATH."
    )
    logger.warning(msg)
    return VecStatus(available=False, error=msg)


def _vec0_works(conn: sqlite3.Connection) -> bool:
    try:
        import sqlite_vec  # type: ignore
        try:
            conn.enable_load_extension(True)
        except Exception:
            pass
        sqlite_vec.load(conn)
        cur = conn.execute("SELECT vec_f32(0.0)")
        cur.fetchone()
        return True
    except sqlite3.OperationalError as e:
        if "no such function" in str(e).lower():
            return False
        return True
    except Exception:
        return False


# ---- Phase 3 KNN + insert ----

def _vec_as_blob(vec: np.ndarray) -> bytes:
    """Pack float32[dim] into a little-endian blob."""
    return struct.pack(f"<{len(vec)}f", *vec.astype(np.float32).flatten())


def _blob_as_vec(blob: bytes, dim: int) -> np.ndarray:
    """Unpack a little-endian blob into float32[dim]."""
    return np.array(struct.unpack(f"<{dim}f", blob[: dim * 4]), dtype=np.float32)


def ensure_vec0_table(conn: sqlite3.Connection, dim: int = EMBED_DIM) -> None:
    """Create the vec0 virtual table if it doesn't exist.

    Idempotent — if the table already exists, silently pass. Must be called
    AFTER sqlite-vec is loaded (e.g. after ``try_enable_vec`` returns available=True).
    """
    try:
        conn.execute(f"CREATE VIRTUAL TABLE IF NOT EXISTS {VEC0_TABLE} USING vec0(embedding float[{dim}])")
    except sqlite3.OperationalError:
        # Already exists, or extension not loaded — silent.
        pass


def insert_vec(
    conn: sqlite3.Connection,
    *,
    rowid: int,       # links to embeddings.id
    vec: np.ndarray,
    dim: int = EMBED_DIM,
) -> None:
    """Insert (or replace) a vector into the vec0 table keyed by rowid."""
    blob = _vec_as_blob(vec)
    conn.execute(
        f"INSERT OR REPLACE INTO {VEC0_TABLE}(rowid, embedding) VALUES (?, ?)",
        (rowid, blob),
    )


def knn_query(
    conn: sqlite3.Connection,
    *,
    query_vec: np.ndarray,
    k: int = 10,
    dim: int = EMBED_DIM,
) -> list[tuple[int, float]]:
    """Return ``[(rowid, distance), ...]`` from a KNN query.

    The distance is a cosine-distance proxy (sqlite-vec uses L2 distance by
    default, but if we use ``normalize_embeddings=True`` in the embedder,
    L2 is equivalent to cosine at scale). Returns empty list on error.
    """
    blob = _vec_as_blob(query_vec)
    try:
        # Use the MATCH operator + K parameter
        cur = conn.execute(
            f"SELECT rowid, distance FROM {VEC0_TABLE} WHERE embedding MATCH ? AND k = ? ORDER BY distance",
            (blob, k),
        )
        return [(int(r[0]), float(r[1])) for r in cur.fetchall()]
    except sqlite3.OperationalError as e:
        logger.debug("knn_query failed: %s", e)
        return []


def delete_vecs_for_binary(conn: sqlite3.Connection, binary_id: int) -> None:
    """Remove vec0 entries for a binary by deleting from the embeddings meta table,
    then cleaning up orphaned vec0 rows.

    Simplest approach: just delete the embeddings rows — the caller should also
    drop and recreate the vec0 table on full rebuild. For targeted delete by
    binary_id, we rely on the embeddings meta table FK chain.
    """
    conn.execute(
        f"DELETE FROM {VEC0_TABLE} WHERE rowid IN (SELECT vec_rowid FROM embeddings WHERE binary_id = ?)",
        (binary_id,),
    )
