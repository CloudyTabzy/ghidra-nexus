"""Unit tests for notebook.scale (Phase 1 / F1)."""

from __future__ import annotations

import pytest

from ghidra_nexus.notebook.scale import (
    _SMALL_FUNCS,
    _MEDIUM_FUNCS,
    _LARGE_FUNCS,
    BinaryScale,
    classify_binary,
)


def _mb(n: int) -> int:
    return n * 1024 * 1024


class TestBothSignalsKnown:
    @pytest.mark.parametrize(
        "size_mb, funcs, expected_cls",
        [
            (1, 100, "small"),               # tiny
            (4, 4_999, "small"),            # near boundary, still small
            (5, 1, "medium"),                # 5MB hits medium; funcs is small; max wins → medium (conservative)
            (5, 5_000, "medium"),            # both push medium
            (24, 29_999, "medium"),          # near upper boundary
            (25, 100, "large"),              # 25MB hits large; max wins → large (conservative)
            (25, 30_000, "large"),           # both push large
            (79, 79_999, "large"),           # near upper boundary
            (80, 1, "very_large"),           # 80MB hits very_large; max wins → very_large
            (80, 80_000, "very_large"),      # both push very_large
            (500, 200_000, "very_large"),    # libpersona-scale
        ],
    )
    def test_classification(self, size_mb, funcs, expected_cls):
        scale = classify_binary(size_bytes=_mb(size_mb), function_count=funcs)
        assert scale.binary_class == expected_cls
        assert isinstance(scale, BinaryScale)


class TestConservativeMax:
    def test_picks_larger_of_size_or_funcs(self):
        # small by size, very_large by funcs → very_large (max wins)
        scale = classify_binary(size_bytes=_mb(1), function_count=200_000)
        assert scale.binary_class == "very_large"


class TestOnlySizeKnown:
    def test_size_only_emit_note(self):
        scale = classify_binary(size_bytes=_mb(50), function_count=None)
        assert scale.binary_class == "unknown_large"
        assert any("function count unknown" in n for n in scale.reliability_notes)

    def test_size_only_unknown_falls_through(self):
        scale = classify_binary(size_bytes=_mb(100), function_count=None)
        assert scale.binary_class == "unknown_very_large"


class TestOnlyFunctionsKnown:
    def test_funcs_only_emit_note(self):
        scale = classify_binary(size_bytes=None, function_count=50_000)
        assert scale.binary_class == "unknown_large"
        assert any("size unknown" in n for n in scale.reliability_notes)


class TestBothUnknown:
    def test_returns_unknown_large(self):
        scale = classify_binary(size_bytes=None, function_count=None)
        # We synthesize an "unknown_large" string the agent can branch on.
        assert scale.binary_class == "unknown_large"
        assert scale.reliability_notes, "must emit a note when both signals are missing"


class TestNotes:
    def test_small_no_notes(self):
        scale = classify_binary(size_bytes=_mb(1), function_count=10)
        assert scale.reliability_notes == []

    def test_medium_emits_notes(self):
        scale = classify_binary(size_bytes=_mb(10), function_count=1000)
        assert scale.reliability_notes

    def test_large_emits_more(self):
        scale = classify_binary(size_bytes=_mb(50), function_count=10_000)
        assert any("section" in n for n in scale.reliability_notes)

    def test_very_large_includes_preheat_hint(self):
        scale = classify_binary(size_bytes=_mb(500), function_count=200_000)
        joined = " ".join(scale.reliability_notes)
        assert "notebook_preheat" in joined

    def test_very_large_includes_search_limit(self):
        scale = classify_binary(size_bytes=_mb(500), function_count=200_000)
        joined = " ".join(scale.reliability_notes)
        assert "search_strings" in joined or "scope" in joined
