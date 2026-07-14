"""sqlite-vec soft-load probe (F12).

This module's *only* job is to attempt to enable the sqlite-vec extension on
a SQLite connection and report whether it worked. **It must never raise**
during ``Notebook.open``: a missing or unloadable extension means we degrade
to FTS-only mode with a loud ``reliability_notes``, never a crash.

**Phase 1:** probe + status object. **Phase 3:** real KNN queries, hybrid
search, embed_worker. **Phase 5:** rebuild/status + Chroma demotion.

Design notes (cross-referenced from foundation-principles.md F12):

- Vendored load strategy: prefer ``sqlite_vec.load(conn)`` from the wheel; honor
  ``SQLITE_VEC_PATH`` env override for manual installs. Never download at runtime.
- Status is *only* :class:`VecStatus`. Callers branch on ``available``.
- Status surfaces through ``analysis_status`` via ``binaries.vec_status`` in
  Phase 3 — for now we expose a top-level probe that Phase 1 callers can
  cache on the ``Notebook`` instance.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from dataclasses import dataclass
from typing import Final


logger = logging.getLogger(__name__)


EMBED_MODEL_ID: Final[str] = "all-MiniLM-L6-v2"
EMBED_DIM: Final[int] = 384


@dataclass(frozen=True)
class VecStatus:
    """Outcome of :func:`try_enable_vec`."""

    available: bool
    error: str | None = None
    dim: int = EMBED_DIM
    model_default: str = EMBED_MODEL_ID


def try_enable_vec(conn: sqlite3.Connection) -> VecStatus:
    """Attempt to load sqlite-vec on ``conn``. Never raises.

    Returns a :class:`VecStatus`. On failure, ``available=False`` and ``error``
    holds a short install hint the agent can surface.

    Implementation notes:
        - We try three load strategies in order:
            1. ``sqlite_vec.load(conn)`` from the wheel (preferred).
            2. ``conn.enable_load_extension(True)`` + ``conn.load_extension(...)``
               from a path set in ``SQLITE_VEC_PATH`` (escape hatch).
            3. Probe ``vec0`` SQL syntax to verify the extension actually works.
        - Each step is wrapped in ``try/except``; any failure logs once at
          WARNING and degrades cleanly.
    """
    # Strategy 1: bundled wheel loader. The wheel's load() does NOT call
    # enable_load_extension(True) for us on Windows; do that first.
    try:
        import sqlite_vec  # type: ignore

        try:
            conn.enable_load_extension(True)
        except Exception:
            pass
        sqlite_vec.load(conn)
        if _vec0_works(conn):
            return VecStatus(available=True)
        return VecStatus(
            available=False, error="sqlite_vec loaded but vec0 unusable"
        )
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

    # Strategy 3: any other failure → degrade
    msg = (
        "sqlite-vec not available. Hybrid search disabled; FTS-only mode. "
        "Install with `uv add sqlite-vec` or set SQLITE_VEC_PATH."
    )
    logger.warning(msg)
    return VecStatus(available=False, error=msg)


def _vec0_works(conn: sqlite3.Connection) -> bool:
    """Confirm the extension loaded by issuing a vec0 probe query.

    We don't actually create a vec0 table here — we only verify the SQL
    extension is present and one of its functions is callable. The wheel's
    ``sqlite_vec.load(conn)`` does NOT call ``enable_load_extension(True)`` for
    us on Windows, so we have to do that here.
    """
    try:
        # ``vec_distance_l2`` is the cheapest probe; it accepts two BLOB args.
        # We pass a literal vector for the first one — but sqlite-vec wants
        # a blob. The cleanest probe is to try a real CREATE VIRTUAL TABLE …
        # except that's expensive. Instead, we just verify the function is
        # registered by issuing an introspection query via ``PRAGMA`` /
        # ``sqlite_master`` style — but that's hard to detect from Python.
        #
        # The pragmatic choice: try the wheel's bundled helper to ensure
        # the extension is loaded + callable. We re-load if needed.
        import sqlite_vec  # type: ignore

        # Some Windows sqlite builds require enable_load_extension(True) before
        # the wheel can attach. Try that, then re-load.
        try:
            conn.enable_load_extension(True)
        except Exception:
            pass
        sqlite_vec.load(conn)
        # Now probe by introspecting the loaded extensions via a dummy call
        # to vec_f32 returning a constant. Some versions return BLOB, some
        # JSON — we just verify the function exists by catching the
        # "no such function" OperationalError specifically.
        cur = conn.execute("SELECT vec_f32(0.0)")
        cur.fetchone()
        return True
    except sqlite3.OperationalError as e:
        # "no such function: vec_f32" means the extension didn't attach.
        if "no such function" in str(e).lower():
            return False
        # Some versions raise OperationalError with input-type complaints;
        # those still mean the extension loaded.
        return True
    except Exception:
        return False
