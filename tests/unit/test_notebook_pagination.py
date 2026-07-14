"""Unit tests for notebook.pagination (Phase 1 / F6)."""

from __future__ import annotations

import pytest

from ghidra_nexus.notebook.pagination import (
    DEFAULT_LIMITS,
    MAX_LIMITS,
    clamp_limit,
    validate_offset,
    window_list,
    window_text,
)


class TestClampLimit:
    @pytest.mark.parametrize("kind", list(DEFAULT_LIMITS.keys()))
    def test_default_when_none(self, kind):
        assert clamp_limit(kind, None) == DEFAULT_LIMITS[kind]

    @pytest.mark.parametrize("kind", list(DEFAULT_LIMITS.keys()))
    def test_max_when_too_large(self, kind):
        assert clamp_limit(kind, MAX_LIMITS[kind] + 1) == MAX_LIMITS[kind]

    @pytest.mark.parametrize("kind", list(DEFAULT_LIMITS.keys()))
    def test_in_range_passes_through(self, kind):
        assert clamp_limit(kind, 10) == 10

    def test_zero_raises(self):
        with pytest.raises(ValueError, match="positive"):
            clamp_limit("xrefs", 0)

    def test_negative_raises(self):
        with pytest.raises(ValueError, match="positive"):
            clamp_limit("xrefs", -1)


class TestValidateOffset:
    def test_default_is_zero(self):
        assert validate_offset("xrefs", None) == 0

    def test_zero_passes(self):
        assert validate_offset("xrefs", 0) == 0

    def test_negative_raises(self):
        with pytest.raises(ValueError, match=">= 0"):
            validate_offset("xrefs", -1)

    def test_huge_raises(self):
        with pytest.raises(ValueError, match="hard limit"):
            validate_offset("xrefs", MAX_LIMITS["xrefs"] * 1_000 + 1)


class TestWindowText:
    def test_empty_input(self):
        w = window_text("")
        assert w.total_lines == 0
        assert w.returned_lines == 0
        assert w.text == ""
        assert w.has_more is False
        assert w.next_offset is None
        assert w.truncated is False

    def test_none_input(self):
        w = window_text(None)
        assert w.total_lines == 0

    def test_short_text_no_windowing(self):
        text = "line1\nline2\nline3"
        w = window_text(text, offset=0, limit=10)
        assert w.text == text
        assert w.total_lines == 3
        assert w.returned_lines == 3
        assert w.has_more is False

    def test_windowed_with_remainder(self):
        text = "\n".join(f"line{i}" for i in range(1, 11))  # 10 lines
        w = window_text(text, offset=0, limit=3)
        assert w.text == "line1\nline2\nline3\n"
        assert w.total_lines == 10
        assert w.returned_lines == 3
        assert w.has_more is True
        assert w.next_offset == 3
        assert w.truncated is True

    def test_second_page(self):
        text = "\n".join(f"line{i}" for i in range(1, 11))
        w = window_text(text, offset=3, limit=3)
        assert w.text == "line4\nline5\nline6\n"
        assert w.next_offset == 6

    def test_final_partial_page(self):
        text = "\n".join(f"line{i}" for i in range(1, 11))
        w = window_text(text, offset=9, limit=5)
        # Input had no trailing newline → last line has none either.
        assert w.text == "line10"
        assert w.returned_lines == 1
        assert w.has_more is False

    def test_no_trailing_newline_keeps_input_shape(self):
        text = "a\nb\nc"  # no trailing newline
        w = window_text(text, offset=0, limit=10)
        assert w.text == text  # unchanged
        assert w.returned_lines == 3

    def test_offset_past_end(self):
        text = "a\nb\nc"
        w = window_text(text, offset=100, limit=10)
        assert w.text == ""
        assert w.returned_lines == 0
        assert w.has_more is False

    def test_offset_negative_clamps_to_zero(self):
        text = "a\nb\nc"
        w = window_text(text, offset=-5, limit=10)
        assert w.offset == 0
        assert w.returned_lines == 3

    def test_as_dict_keys(self):
        w = window_text("a\nb", offset=0, limit=10)
        d = w.as_dict()
        assert set(d.keys()) == {
            "text", "offset", "limit", "total", "returned",
            "has_more", "next_offset", "truncated",
        }


class TestWindowList:
    def test_empty(self):
        w = window_list([])
        assert w["items"] == []
        assert w["total"] == 0
        assert w["has_more"] is False

    def test_short(self):
        w = window_list([1, 2, 3], offset=0, limit=10)
        assert w["items"] == [1, 2, 3]
        assert w["returned"] == 3

    def test_paged(self):
        w = window_list(list(range(10)), offset=0, limit=3)
        assert w["items"] == [0, 1, 2]
        assert w["next_offset"] == 3

    def test_final_page(self):
        w = window_list(list(range(10)), offset=9, limit=5)
        assert w["items"] == [9]
        assert w["has_more"] is False

    def test_negative_offset_clamps(self):
        w = window_list([1, 2, 3], offset=-2, limit=10)
        assert w["offset"] == 0
        assert w["items"] == [1, 2, 3]
