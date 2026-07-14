"""Chat prompt templates for SLM tasks (Phase 6).

Each task has a system prompt + user template. The output is a JSON object
matching the per-task schema in :mod:`ghidra_nexus.slm.tasks`. The SLM
receives the full prompt as a chat message and returns a string we parse.

Templates are kept short and explicit:
- Output format: always JSON, no prose
- Constraints: token count, identifier rules
- Grounding: explicit reminder that invented names are rejected
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ChatPrompt:
    """A prepared prompt ready to feed to the SLM."""

    system: str
    user: str
    json_schema_hint: dict[str, Any]  # for prompt construction; not enforced at runtime


# ---------------------------------------------------------------------------
# 1. query_expand
# ---------------------------------------------------------------------------

_QUERY_EXPAND_SYSTEM = """\
You are a reverse engineer. Reformulate a natural-language search query into
machine-friendly search terms against a disassembled binary.

Output format: strict JSON object, no prose, no markdown fences.
{
  "tokens": [str, ...],          // ≤ 20 lowercase snake_case tokens
  "related_apis": [str, ...],    // ≤ 8 real Windows/POSIX API names
  "fts_query": str,              // ≤ 500 chars; OR-joined tokens
  "rationale": str              // ≤ 200 chars; one sentence
}

Rules:
- Tokens are lowercase snake_case, ≤ 32 chars, valid C identifiers.
- related_apis must be REAL Windows or POSIX API names. No invented APIs.
- fts_query is the OR-joined tokens, with double-quoted phrases where useful.
- All function/symbol names must appear in the input — do not invent.
- If the query is already a function name, return it in tokens unchanged.
- If the query is unparseable, return {"tokens": [], "related_apis": [], "fts_query": "", "rationale": "unparseable"}.
"""


def build_query_expand_prompt(
    *,
    query: str,
    binary_name: str,
    known_aliases: list[str] | None = None,
    known_apis: list[str] | None = None,
) -> ChatPrompt:
    """Build a query_expand prompt for the given natural-language query."""
    user_lines = [
        f"RAW QUERY: {query!r}",
        f"BINARY: {binary_name}",
    ]
    if known_aliases:
        # Cap to keep prompt short
        sample = sorted(set(known_aliases))[:50]
        user_lines.append(
            "EXISTING ALIASES (function names already known in this binary): "
            + ", ".join(sample)
        )
    if known_apis:
        sample = sorted(set(known_apis))[:30]
        user_lines.append(
            "API NAMES MENTIONED ELSEWHERE IN THIS BINARY: " + ", ".join(sample)
        )
    user_lines.append(
        "Reformulate the raw query. Output only the JSON object, no other text."
    )
    return ChatPrompt(
        system=_QUERY_EXPAND_SYSTEM,
        user="\n".join(user_lines),
        json_schema_hint={
            "type": "object",
            "properties": {
                "tokens": {"type": "array", "items": {"type": "string"}},
                "related_apis": {"type": "array", "items": {"type": "string"}},
                "fts_query": {"type": "string"},
                "rationale": {"type": "string"},
            },
            "required": ["tokens", "related_apis", "fts_query", "rationale"],
        },
    )


# ---------------------------------------------------------------------------
# 2. summarize
# ---------------------------------------------------------------------------

_SUMMARIZE_SYSTEM = """\
You are a reverse engineer writing a brief comment for a decompiled function.

Output format: strict JSON object, no prose, no markdown fences.
{"summary": str, "subsystem_hint": str | null}

Rules:
- summary: 1-3 sentences, ≤ 500 chars. Concise. Specific.
- All function/symbol names mentioned must appear in the input.
- subsystem_hint: 1-4 word tag (e.g. "network I/O", "string parsing", "registry"). null if unclear.
- If the body is empty or trivial (single ret), say so directly.
"""


def build_summarize_prompt(
    *,
    body: str,
    style: str = "purpose",  # "purpose" | "side_effects" | "callers"
    alias: str | None = None,
    callers: list[str] | None = None,
    callees: list[str] | None = None,
) -> ChatPrompt:
    style_desc = {
        "purpose": "What does this function accomplish?",
        "side_effects": "What state does it mutate (globals, files, network)?",
        "callers": "Who calls this and in what context?",
    }.get(style, "What does this function accomplish?")
    user_lines = [
        f"STYLE: {style} — {style_desc}",
    ]
    if alias:
        user_lines.append(f"Function alias: {alias}")
    user_lines.append("DECOMPILED BODY:")
    user_lines.append(body[:4000])  # cap body to keep prompt short
    if callers:
        user_lines.append(
            "CALLERS: " + ", ".join(sorted(set(callers))[:10])
        )
    if callees:
        user_lines.append(
            "CALLEES: " + ", ".join(sorted(set(callees))[:10])
        )
    user_lines.append("Output only the JSON object, no other text.")
    return ChatPrompt(
        system=_SUMMARIZE_SYSTEM,
        user="\n".join(user_lines),
        json_schema_hint={
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "subsystem_hint": {"type": "string"},
            },
            "required": ["summary"],
        },
    )


# ---------------------------------------------------------------------------
# 3. suggest_name
# ---------------------------------------------------------------------------

_SUGGEST_NAME_SYSTEM = """\
You are a reverse engineer naming a function.

Output format: strict JSON array, no prose, no markdown fences.
[
  {"name": str, "confidence": float, "rationale": str},
  ...
]

Rules:
- Names: snake_case, ≤ 5 words, ≤ 64 chars.
- confidence: 0.0 (pure guess) to 1.0 (multiple strong signals align).
- 1-3 candidates sorted by confidence desc.
- rationale: ≤ 200 chars, one sentence, references input.
- All function/API names mentioned must appear in the input. No inventing.
- If the body is trivial (empty / single ret), return [].
- If no good name is possible, return [].
"""


def build_suggest_name_prompt(
    *,
    body: str,
    called_apis: list[str] | None = None,
    string_refs: list[str] | None = None,
    callers: list[str] | None = None,
    callees: list[str] | None = None,
    other_aliases: list[str] | None = None,
) -> ChatPrompt:
    user_lines = ["DECOMPILED BODY:", body[:4000]]
    if called_apis:
        user_lines.append(
            "CALLED APIs: " + ", ".join(sorted(set(called_apis))[:20])
        )
    if string_refs:
        user_lines.append(
            "STRING REFERENCES: " + ", ".join(
                repr(s) for s in sorted(set(string_refs))[:10]
            )
        )
    if callers:
        user_lines.append(
            "CALLERS: " + ", ".join(sorted(set(callers))[:10])
        )
    if callees:
        user_lines.append(
            "CALLEES: " + ", ".join(sorted(set(callees))[:10])
        )
    if other_aliases:
        user_lines.append(
            "EXISTING ALIASES IN THIS BINARY (style reference): "
            + ", ".join(sorted(set(other_aliases))[:30])
        )
    user_lines.append(
        "Propose 1-3 candidate names. Output only the JSON array, no other text."
    )
    return ChatPrompt(
        system=_SUGGEST_NAME_SYSTEM,
        user="\n".join(user_lines),
        json_schema_hint={
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "confidence": {"type": "number"},
                    "rationale": {"type": "string"},
                },
                "required": ["name", "confidence", "rationale"],
            },
        },
    )


# ---------------------------------------------------------------------------
# 4. explain_callgraph
# ---------------------------------------------------------------------------

_EXPLAIN_CALLGRAPH_SYSTEM = """\
You are a reverse engineer summarizing a function in the context of its
caller / callee neighborhood.

Output format: strict JSON object, no prose, no markdown fences.
{
  "summary": str,                  // 2-3 sentences, ≤ 400 chars
  "subsystem_hint": str | null,    // 1-4 word tag, or null
  "key_paths": [str, ...]          // 1-3 call paths, formatted "A → B → C"
}

Rules:
- All function names mentioned must appear in the input.
- key_paths use names from the input only; no invented names.
- If the function is trivial (no callers, no callees, empty body), say so.
- Be specific. Avoid filler like "this function does various things".
"""


def build_explain_callgraph_prompt(
    *,
    target_name: str,
    target_rva: str,
    body_excerpt: str,
    callers: list[str],
    callees: list[str],
) -> ChatPrompt:
    user_lines = [
        f"TARGET: {target_name} @ {target_rva}",
        "BODY (first 2000 chars):",
        body_excerpt[:2000],
    ]
    if callers:
        user_lines.append(
            f"CALLERS ({len(callers)}): "
            + ", ".join(sorted(set(callers))[:15])
        )
    if callees:
        user_lines.append(
            f"CALLEES ({len(callees)}): "
            + ", ".join(sorted(set(callees))[:15])
        )
    user_lines.append(
        "Output only the JSON object, no other text."
    )
    return ChatPrompt(
        system=_EXPLAIN_CALLGRAPH_SYSTEM,
        user="\n".join(user_lines),
        json_schema_hint={
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "subsystem_hint": {"type": "string"},
                "key_paths": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary"],
        },
    )
