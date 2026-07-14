"""Pagination helpers (F6 — large-result protocol).

Full blobs live in the notebook; the wire shows only what the agent asked for.
Every MCP tool response that returns text or list output should be windowed through
these helpers so a 50 000-line decompile doesn't blow the agent's context window.

Envelope shape (used by Phase 2+ handlers):

.. code-block:: python

    {
        "text": "...",       # the window
        "offset": 0,         # start of this window
        "limit": 200,        # how many lines / items requested
        "total": 1234,       # total size of the underlying blob
        "returned": 200,     # how many lines / items actually returned
        "has_more": true,    # window is a strict prefix of the rest
        "next_offset": 200,  # pass this back to fetch the next page
        "truncated": true,   # True iff truncated on the wire
    }
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Default and hard limits
# ---------------------------------------------------------------------------

DEFAULT_LIMITS: dict[str, int] = {
    "decompile_lines": 200,
    "disasm_insns": 40,
    "xrefs": 50,
    "strings": 100,
    "functions": 100,
    "fts": 20,
    "breadcrumbs": 50,
}

MAX_LIMITS: dict[str, int] = {
    "decompile_lines": 2_000,
    "disasm_insns": 500,
    "xrefs": 500,
    "strings": 1_000,
    "functions": 1_000,
    "fts": 100,
    "breadcrumbs": 500,
}


def clamp_limit(kind: str, requested: int | None) -> int:
    """Clamp a requested page size to ``[1, MAX_LIMITS[kind]]``.

    ``None`` → default for the kind. Negative or zero values raise ``ValueError``
    so the agent sees a structured error early rather than a silent off-by-one.
    """
    if requested is None:
        return DEFAULT_LIMITS[kind]
    if requested <= 0:
        raise ValueError(
            f"limit for {kind!r} must be positive, got {requested}"
        )
    cap = MAX_LIMITS[kind]
    if requested > cap:
        return cap
    return requested


def validate_offset(kind: str, offset: int | None) -> int:
    """Validate an offset against ``MAX_LIMITS[kind]``.

    We don't know the *total* here (the caller passes that in), so we only verify
    the offset is non-negative and not absurdly large.
    """
    if offset is None:
        return 0
    if offset < 0:
        raise ValueError(f"offset for {kind!r} must be >= 0, got {offset}")
    cap = MAX_LIMITS[kind] * 1_000  # generous hard limit
    if offset > cap:
        raise ValueError(
            f"offset {offset} exceeds hard limit {cap} for {kind!r}; "
            "consider notebook_summary instead"
        )
    return offset


# ---------------------------------------------------------------------------
# Text window
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PageWindow:
    """A text window with full provenance for the agent."""

    text: str
    offset: int
    limit: int
    total_lines: int
    returned_lines: int
    has_more: bool
    next_offset: int | None
    truncated: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "offset": self.offset,
            "limit": self.limit,
            "total": self.total_lines,
            "returned": self.returned_lines,
            "has_more": self.has_more,
            "next_offset": self.next_offset,
            "truncated": self.truncated,
        }


def window_text(
    full: str | None,
    *,
    offset: int = 0,
    limit: int = DEFAULT_LIMITS["decompile_lines"],
) -> PageWindow:
    """Return a windowed slice of a text blob.

    ``offset`` and ``limit`` operate on **lines** (splitlines). Empty or None
    input returns an empty window with ``total_lines=0``.
    """
    if not full:
        return PageWindow(
            text="",
            offset=offset,
            limit=limit,
            total_lines=0,
            returned_lines=0,
            has_more=False,
            next_offset=None,
            truncated=False,
        )

    lines = full.splitlines(keepends=True)
    total = len(lines)
    safe_offset = max(0, min(offset, total))
    safe_limit = max(0, limit)
    chunk = lines[safe_offset : safe_offset + safe_limit]
    returned = len(chunk)

    end_idx = safe_offset + returned
    has_more = end_idx < total
    next_offset = end_idx if has_more else None

    # Reassemble the window without trailing-newline drift.
    text = "".join(chunk)

    return PageWindow(
        text=text,
        offset=safe_offset,
        limit=safe_limit,
        total_lines=total,
        returned_lines=returned,
        has_more=has_more,
        next_offset=next_offset,
        truncated=has_more,
    )


# ---------------------------------------------------------------------------
# List window
# ---------------------------------------------------------------------------

def window_list(
    items: list,
    *,
    offset: int = 0,
    limit: int = DEFAULT_LIMITS["xrefs"],
) -> dict[str, Any]:
    """Same envelope as :func:`window_text` but for arbitrary lists.

    Returns the standard envelope dict (text/list field is named ``items``).
    """
    if not items:
        return {
            "items": [],
            "offset": offset,
            "limit": limit,
            "total": 0,
            "returned": 0,
            "has_more": False,
            "next_offset": None,
            "truncated": False,
        }

    total = len(items)
    safe_offset = max(0, min(offset, total))
    safe_limit = max(0, limit)
    chunk = items[safe_offset : safe_offset + safe_limit]
    returned = len(chunk)

    end_idx = safe_offset + returned
    has_more = end_idx < total

    return {
        "items": chunk,
        "offset": safe_offset,
        "limit": safe_limit,
        "total": total,
        "returned": returned,
        "has_more": has_more,
        "next_offset": end_idx if has_more else None,
        "truncated": has_more,
    }
