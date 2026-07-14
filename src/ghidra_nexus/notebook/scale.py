"""Binary scale classifier (F1 — capability envelope).

Every notebook entry is tagged with one of four size classes; the ``reliability_notes``
list steers the agent toward safe queries for the larger ones. These notes surface
through ``analysis_status`` so an LLM agent can self-adapt without trial-and-error.

Thresholds (tunable via tests):

================  ========  =========
Class             Size MB   Funcs
================  ========  =========
small               <5        <5k
medium              <25       <30k
large               <80       <80k
very_large           else      else
================  ========  =========
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


BinaryClass = Literal[
    "small",
    "medium",
    "large",
    "very_large",
    "unknown_small",
    "unknown_medium",
    "unknown_large",
    "unknown_very_large",
]


_SMALL_SIZE_BYTES = 5 * 1024 * 1024
_MEDIUM_SIZE_BYTES = 25 * 1024 * 1024
_LARGE_SIZE_BYTES = 80 * 1024 * 1024
_SMALL_FUNCS = 5_000
_MEDIUM_FUNCS = 30_000
_LARGE_FUNCS = 80_000


@dataclass(frozen=True)
class BinaryScale:
    """Scale classification result."""

    binary_class: BinaryClass
    reliability_notes: list[str]


def classify_binary(*, size_bytes: int | None, function_count: int | None) -> BinaryScale:
    """Return a :class:`BinaryScale` for the given binary.

    Either ``size_bytes`` or ``function_count`` may be None (Ghidra may not have
    discovered either yet). In that case we fall back to ``unknown_<cls>`` so the
    agent can see the estimate was uncertain.
    """
    notes: list[str] = []
    size_mb = (size_bytes / (1024 * 1024)) if size_bytes else None

    # If both signals are missing we can't say anything useful.
    if size_mb is None and function_count is None:
        return BinaryScale(
            binary_class="unknown_large",
            reliability_notes=[
                "binary size and function count are both unknown; treat as large and "
                "avoid unbounded enumerations"
            ],
        )

    # Default to the conservative class; tighten if both signals agree.
    if size_mb is None:
        # size unknown — trust function_count only, mark variant.
        cls = _class_from_funcs_only(function_count or 0)
        return BinaryScale(
            binary_class=_unknown_variant(cls),
            reliability_notes=[
                "binary size unknown; capability envelope estimated from function count only"
            ],
        )

    if function_count is None:
        # function count unknown — trust size only, mark variant.
        cls = _class_from_size_only(size_mb)
        return BinaryScale(
            binary_class=_unknown_variant(cls),
            reliability_notes=[
                "function count unknown; capability envelope estimated from file size only"
            ],
        )

    # Both known: take the larger of the two classes (conservative).
    cls_size = _class_from_size_only(size_mb)
    cls_funcs = _class_from_funcs_only(function_count)
    cls = _max_class(cls_size, cls_funcs)

    if cls != "small":
        notes.extend(_notes_for_class(cls))
    return BinaryScale(binary_class=cls, reliability_notes=notes)


def _class_from_size_only(size_mb: float) -> BinaryClass:
    if size_mb < 5:
        return "small"
    if size_mb < 25:
        return "medium"
    if size_mb < 80:
        return "large"
    return "very_large"


def _class_from_funcs_only(funcs: int) -> BinaryClass:
    if funcs < _SMALL_FUNCS:
        return "small"
    if funcs < _MEDIUM_FUNCS:
        return "medium"
    if funcs < _LARGE_FUNCS:
        return "large"
    return "very_large"


_CLASS_ORDER = [
    "small",
    "unknown_small",
    "medium",
    "unknown_medium",
    "large",
    "unknown_large",
    "very_large",
    "unknown_very_large",
]


def _max_class(a: BinaryClass, b: BinaryClass) -> BinaryClass:
    return a if _CLASS_ORDER.index(a) >= _CLASS_ORDER.index(b) else b


def _unknown_variant(cls: str) -> str:
    """Map a known class to its ``unknown_*`` counterpart."""
    return "unknown_" + cls


def _notes_for_class(cls: BinaryClass) -> list[str]:
    """Per-class reliability notes surfaced via analysis_status.

    Notes steer the agent toward safe query patterns for that class.
    """
    if cls == "medium":
        return [
            "use tight search_strings queries; prefer literal mode for short tokens",
            "decompile one function at a time; rely on notebook windows",
        ]
    if cls == "large":
        return [
            "prefer targeted search_strings over unbounded enumeration",
            "scope find_similar_functions / callgraph to a section",
            "decompile one function at a time; rely on notebook windows",
            "avoid binary-wide string enumeration without limit",
        ]
    if cls == "very_large":
        return [
            "this binary is large; default searches return limited windows",
            "scope find_similar_functions / callgraph to a section or single function",
            "empty/short search_strings queries may be refused",
            "avoid full-binary callgraph — use gen_callgraph(root, depth=2) at most",
            "consider notebook_preheat before interactive analysis",
        ]
    return []
