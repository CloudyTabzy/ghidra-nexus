"""Unit tests for ghidra_nexus.section_entropy — pure-Python entropy helpers.

These don't need Ghidra. Real Ghidra integration is tested in
``tests/integration``.
"""

from __future__ import annotations

import math

import pytest

from ghidra_nexus.models import SectionClassification, SectionRecommendation
from ghidra_nexus.section_entropy import (
    classify_section,
    shannon_entropy,
    summarize_section_classifications,
)


class TestShannonEntropy:
    def test_uniform_distribution_full(self):
        # Uniform across all 256 byte values — should give ~8 bits/byte
        data = bytes(range(256)) * 4  # 1024 bytes
        e = shannon_entropy(data)
        assert math.isclose(e, 8.0, abs_tol=0.05)

    def test_uniform_over_subset_is_lower_than_8(self):
        # Only 16 distinct values — should give exactly 4 bits/byte
        data = (bytes(range(16)) * 64)  # 1024 bytes, 16 unique
        e = shannon_entropy(data)
        assert math.isclose(e, 4.0, abs_tol=0.05)

    def test_constant_byte_is_zero(self):
        data = bytes([0x5A] * 1024)
        assert shannon_entropy(data) == pytest.approx(0.0)

    def test_empty_input_returns_zero(self):
        assert shannon_entropy(b"") == 0.0
        assert shannon_entropy(bytearray()) == 0.0

    def test_high_entropy_section_example(self):
        # Random-looking bytes; should be > 7
        import random

        random.seed(0)
        data = bytes(random.randint(0, 255) for _ in range(4096))
        e = shannon_entropy(data)
        assert e > 7.5


class TestClassifySection:
    def test_high_entropy_executable_classified_encrypted(self):
        # Even if executable, very high entropy → encrypted
        cls, rec, reason = classify_section(
            entropy=7.95, size_bytes=10 * 1024 * 1024, is_executable=True
        )
        assert cls is SectionClassification.ENCRYPTED
        assert rec is SectionRecommendation.DUMP_RUNTIME
        assert "encrypted" in reason.lower()

    def test_low_entropy_data_classified_data_with_skip(self):
        cls, rec, reason = classify_section(
            entropy=3.5, size_bytes=4096, is_executable=False
        )
        assert cls is SectionClassification.DATA
        assert rec is SectionRecommendation.SKIP

    def test_low_entropy_executable_classified_code(self):
        cls, rec, _ = classify_section(
            entropy=5.0, size_bytes=4096, is_executable=True
        )
        assert cls is SectionClassification.CODE
        assert rec is SectionRecommendation.ANALYZE

    def test_medium_entropy_classified_compressed(self):
        cls, rec, _ = classify_section(
            entropy=6.2, size_bytes=1024 * 1024, is_executable=False
        )
        assert cls is SectionClassification.COMPRESSED
        assert rec is SectionRecommendation.DECOMPRESS

    def test_tiny_section_marked_unknown(self):
        cls, _, _ = classify_section(entropy=4.0, size_bytes=4, is_executable=False)
        assert cls is SectionClassification.UNKNOWN


class TestSummarizeSectionClassifications:
    def test_no_sections_is_normal(self):
        assert summarize_section_classifications([]) == "normal"

    def test_pure_encrypted(self):
        assert (
            summarize_section_classifications([SectionClassification.ENCRYPTED])
            == "encrypted"
        )

    def test_pure_code(self):
        assert (
            summarize_section_classifications(
                [SectionClassification.CODE, SectionClassification.CODE]
            )
            == "normal"
        )

    def test_mixed_code_and_encrypted_is_mixed(self):
        assert (
            summarize_section_classifications(
                [SectionClassification.CODE, SectionClassification.ENCRYPTED]
            )
            == "mixed"
        )

    def test_only_compressed_is_compressed(self):
        assert (
            summarize_section_classifications([SectionClassification.COMPRESSED])
            == "compressed"
        )
