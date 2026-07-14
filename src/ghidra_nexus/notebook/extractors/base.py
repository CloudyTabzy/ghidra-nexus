"""Schema-aware extractors (F11) — base classes, protocol, registry.

Every successful cache write-through invokes a registered extractor for the
tool family. The extractor returns a deterministic :class:`ExtractedView` with
``summary`` + ``key_entities``; we store that in ``artifact_views`` and feed
``name + summary + entities`` to FTS5 and (in Phase 3) to sqlite-vec.

This is the **noise gate** — without an LLM relevance judge, deterministic
extraction keeps the search index focused on domain fields and strips
transport boilerplate. Bad summaries are debugged by iterating the extractor
regexes, never by tweaking an LLM prompt.

Phase 1 ships the protocol + a stub registry + the decompile stub. Phase 2
fills in the per-family extractors (decompile, disasm, xrefs, strings,
section_health, survey).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol


@dataclass
class KeyEntity:
    """One extracted entity, grounded in the input payload.

    Values SHOULD be substrings of the input — the agent can verify
    by grepping the source code for ``value``. ``rva`` is set when the
    entity refers to a code address (callee, instruction immediate).
    """

    kind: str  # api | string | imm | callee | section | import | name | warning
    value: str
    rva: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "value": self.value}
        if self.rva is not None:
            out["rva"] = self.rva
        return out


@dataclass
class ExtractedView:
    """Result of running an extractor on a tool result payload."""

    summary: str
    key_entities: list[KeyEntity] = field(default_factory=list)
    view_model: str = "extractive_v1"
    quality_hint: str | None = None  # "ok" | "stub" | "empty" | "encrypted"

    def entities_json(self) -> str:
        """JSON array of entities (for storage in ``artifact_views.key_entities``)."""
        import json

        return json.dumps([e.to_dict() for e in self.key_entities], ensure_ascii=False)

    def search_blob(self) -> str:
        """Text to feed FTS5 (and Phase 3 sqlite-vec embedding).

        Concatenates the function name + summary + joined entities so the search
        index captures intent without re-indexing the entire raw blob.
        """
        parts: list[str] = []
        if self.summary:
            parts.append(self.summary)
        for e in self.key_entities:
            parts.append(f"{e.kind}:{e.value}")
        return "\n".join(parts)


class Extractor(Protocol):
    """Protocol every extractor implements.

    ``payload`` is tool-family-specific. The extractor must be **pure** — no I/O,
    no LLM, fast (<5 ms typical). The ``kind`` is the cache row kind ("decompile",
    "disasm", "xrefs", "strings", "section_health", "survey").
    """

    kind: str

    def extract(self, payload: dict[str, Any]) -> ExtractedView: ...


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, Extractor] = {}


def register(extractor: Extractor) -> None:
    """Register an extractor. Replaces any existing extractor for the same ``kind``."""
    _REGISTRY[extractor.kind] = extractor


def get(kind: str) -> Extractor | None:
    return _REGISTRY.get(kind)


def kinds() -> list[str]:
    """Return registered extractor kinds (sorted, copy)."""
    return sorted(_REGISTRY.keys())


def extract_for(kind: str, payload: dict[str, Any]) -> ExtractedView | None:
    """Look up the registered extractor and run it. Returns ``None`` if no extractor.

    Never raises — if extraction fails, the caller can fall back to an empty view
    so the cache write-through still succeeds. The error is logged by the caller.
    """
    extractor = _REGISTRY.get(kind)
    if extractor is None:
        return None
    try:
        return extractor.extract(payload)
    except Exception:
        # Caller logs and falls back. Don't poison the cache write on bad extract.
        return None


def reset_for_testing() -> None:
    """Clear the registry. Tests-only — do not call from production code."""
    _REGISTRY.clear()
