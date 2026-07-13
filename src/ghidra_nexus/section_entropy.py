"""Section entropy + classification utilities.

Lives outside :mod:`api_survey` so we can unit-test the math without booting Ghidra.
Pure-Python — uses :mod:`math` only; no numpy, no platform deps.
"""

from __future__ import annotations

import math
from typing import Iterable

from ghidra_nexus.models import SectionClassification, SectionRecommendation


def shannon_entropy(data: bytes | bytearray | memoryview | Iterable[int]) -> float:
    """Shannon entropy in bits/byte over the input.

    Returns 0.0 for an empty input. Pure-Python, no numpy.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    total = 0
    for byte in data:
        counts[byte] += 1
        total += 1
    if total == 0:
        return 0.0
    entropy = 0.0
    inv_total = 1.0 / total
    for count in counts:
        if count == 0:
            continue
        p = count * inv_total
        entropy -= p * math.log2(p)
    return entropy


def classify_section(
    entropy: float,
    size_bytes: int,
    *,
    is_executable: bool,
) -> tuple[SectionClassification, SectionRecommendation, str]:
    """Classify a section and recommend an action.

    Returns ``(classification, recommendation, reason)``.

    The classification function accounts for the fact that *very small* sections
    produce noisy entropy values, so we mark them ``UNKNOWN`` instead of guessing.

    The recommendation uses entropy + executability:

    - ``encrypted`` (entropy >= 7.0) → ``dump_runtime`` (need to run the binary)
    - ``compressed`` (5.5-7.0)       → ``decompress`` (need a decompressor pass)
    - ``code`` executable            → ``analyze`` (normal path)
    - ``code`` non-executable        → ``skip``   (typically padding or junk)
    - ``data`` (low-entropy non-X)   → ``skip``
    - ``UNKNOWN``                     → ``analyze`` (let agent decide)
    """
    if size_bytes < 16:
        return (
            SectionClassification.UNKNOWN,
            SectionRecommendation.ANALYZE,
            f"section is only {size_bytes} bytes; entropy estimate unreliable",
        )

    if entropy >= 7.0:
        return (
            SectionClassification.ENCRYPTED,
            SectionRecommendation.DUMP_RUNTIME,
            f"entropy {entropy:.2f} >= 7.0 — section appears encrypted at rest; needs runtime dump",
        )
    if entropy >= 5.5:
        return (
            SectionClassification.COMPRESSED,
            SectionRecommendation.DECOMPRESS,
            f"entropy {entropy:.2f} in 5.5..7.0 — section appears compressed; decompress before analysis",
        )
    if not is_executable:
        return (
            SectionClassification.DATA,
            SectionRecommendation.SKIP,
            f"entropy {entropy:.2f}, non-executable — looks like static data; skip unless strings indicate otherwise",
        )
    return (
        SectionClassification.CODE,
        SectionRecommendation.ANALYZE,
        f"entropy {entropy:.2f}, executable — looks like code; normal analyze path",
    )


def summarize_section_classifications(
    classifications: Iterable[SectionClassification],
) -> str:
    """Return the top-level :class:`EntropySummary` value for the survey.

    Used by ``analysis_status`` to tell the agent at a glance whether any section
    looks encrypted/compressed, without forcing the agent to iterate every
    section manually first.
    """
    seen = set(classifications)
    if not seen:
        return "normal"
    if SectionClassification.ENCRYPTED in seen:
        # Mixed if some sections are still normal; pure encrypted otherwise.
        if SectionClassification.CODE in seen or SectionClassification.DATA in seen:
            return "mixed"
        return "encrypted"
    if SectionClassification.COMPRESSED in seen:
        if SectionClassification.CODE in seen or SectionClassification.DATA in seen:
            return "mixed"
        return "compressed"
    if SectionClassification.UNKNOWN in seen and len(seen) == 1:
        return "normal"
    return "normal"
