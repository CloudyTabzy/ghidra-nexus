"""SLM task runners (Phase 6).

Each ``run_*`` function:
1. Builds a prompt via :mod:`ghidra_nexus.slm.prompts`.
2. Calls the SLM via :mod:`ghidra_nexus.slm.loader`.
3. Parses + grounds the output via :mod:`ghidra_nexus.slm.grounding`.
4. Returns a result dataclass or raises.

Runners are **synchronous** in the SLM layer; the async wrapping happens
at the MCP tool boundary. Runners must NOT block longer than
``NEXUS_SLM_TIMEOUT_SEC``.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass

from ghidra_nexus.slm.grounding import (
    validate_api_name,
    validate_fts_query,
    validate_identifier,
    validate_summary,
    validate_token,
)
from ghidra_nexus.slm.loader import get_model
from ghidra_nexus.slm.prompts import (
    ChatPrompt,
    build_explain_callgraph_prompt,
    build_query_expand_prompt,
    build_suggest_name_prompt,
    build_summarize_prompt,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclasses (one per task)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExpandedQuery:
    raw_query: str
    tokens: list[str]
    related_apis: list[str]
    fts_query: str
    rationale: str
    model: str
    latency_ms: int


@dataclass(frozen=True)
class NameCandidate:
    name: str
    confidence: float
    rationale: str


@dataclass(frozen=True)
class SuggestNameResult:
    candidates: list[NameCandidate]
    binary_name: str
    rva: str
    model: str
    latency_ms: int


@dataclass(frozen=True)
class SummarizeResult:
    summary: str
    subsystem_hint: str | None
    binary_name: str
    rva: str
    style: str
    model: str
    latency_ms: int


@dataclass(frozen=True)
class CallgraphExplanation:
    summary: str
    subsystem_hint: str | None
    key_paths: list[str]
    binary_name: str
    rva: str
    depth: int
    model: str
    latency_ms: int


# ---------------------------------------------------------------------------
# SLM invocation helper
# ---------------------------------------------------------------------------


def _invoke_slm(
    prompt: ChatPrompt,
    *,
    max_new_tokens: int = 256,
    timeout_sec: int = 30,
) -> tuple[str, int]:
    """Run the SLM on a prepared prompt. Returns (raw_text, latency_ms).

    Raises RuntimeError on timeout / generation failure.
    """
    tokenizer, model, _cfg = get_model()

    messages = [
        {"role": "system", "content": prompt.system},
        {"role": "user", "content": prompt.user},
    ]

    # Build the chat template once. Some models (Qwen) put system in the
    # first user turn; AutoTokenizer's chat template handles this.
    input_text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )
    inputs = tokenizer(input_text, return_tensors="pt")
    try:
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
    except Exception:
        # Some quantized / device-mapped models refuse .to() — fall through.
        pass

    t0 = time.time()
    try:
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    except Exception as e:
        raise RuntimeError(f"SLM generation failed: {e}") from e
    latency_ms = int((time.time() - t0) * 1000)

    new_tokens = outputs[0][inputs["input_ids"].shape[1]:]
    text = tokenizer.decode(new_tokens, skip_special_tokens=True)
    return text, latency_ms


def _extract_json(text: str) -> dict | list | None:
    """Extract the outermost balanced JSON object or array from a model response.

    Models sometimes wrap output in markdown fences (``\\`\\`\\`json ... \\`\\`\\`\\``)
    or add leading prose ("Here's the answer: { ... }").

    Strategy:
      1. Find the FIRST opening brace/bracket after stripping fences.
      2. Match its closing counterpart (handles nested structures and
         strings with escaped quotes).
      3. Try to parse that span.
      4. If parse fails, return None — do NOT silently fall through to an
         inner span, which would mislead the caller (e.g. extracting just
         ``["raw", "query"]`` from a malformed outer object).

    If the first opening brace is a ``[`` (e.g. the model returned a bare
    array), that's fine; we just match the ``]``.
    """
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"```\s*$", "", text)

    # Find the FIRST opening brace or bracket.
    first_open_idx = -1
    first_open_ch = ""
    first_close_ch = ""
    for i, ch in enumerate(text):
        if ch in "{[":
            first_open_idx = i
            first_open_ch = ch
            first_close_ch = "}" if ch == "{" else "]"
            break

    if first_open_idx == -1:
        # No JSON-like structure at all
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    # Walk forward from the first opener, tracking depth + string state.
    depth = 0
    in_str = False
    escape = False
    for j in range(first_open_idx, len(text)):
        c = text[j]
        if escape:
            escape = False
            continue
        if c == "\\":
            escape = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == first_open_ch:
            depth += 1
        elif c == first_close_ch:
            depth -= 1
            if depth == 0:
                candidate = text[first_open_idx:j + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    # Outer span failed to parse. Do NOT fall through to
                    # an inner span — return None so the caller falls back
                    # to a heuristic rather than receiving a misleading
                    # fragment.
                    return None

    # Unmatched brace — give up gracefully.
    return None


# ---------------------------------------------------------------------------
# 1. run_query_expand
# ---------------------------------------------------------------------------


def run_query_expand(
    *,
    binary_name: str,
    query: str,
    known_aliases: list[str] | None = None,
    known_apis: list[str] | None = None,
    max_tokens: int = 20,
    timeout_sec: int = 30,
) -> ExpandedQuery:
    """Reformulate a natural-language query into FTS-friendly tokens.

    The output is **grounded**: every token is validated, every API name
    is checked against the built-in catalog, and the fts_query is sanity-
    checked. On any grounding failure, the function falls back to a
    minimal expansion (raw query lowercased + split on whitespace) so the
    caller still gets *something* useful.
    """
    if not query or not query.strip():
        return ExpandedQuery(
            raw_query=query,
            tokens=[],
            related_apis=[],
            fts_query="",
            rationale="empty query",
            model="<unknown>",
            latency_ms=0,
        )

    prompt = build_query_expand_prompt(
        query=query,
        binary_name=binary_name,
        known_aliases=known_aliases,
        known_apis=known_apis,
    )

    raw_text, latency_ms = _invoke_slm(
        prompt, max_new_tokens=200, timeout_sec=timeout_sec
    )
    parsed = _extract_json(raw_text)
    if not isinstance(parsed, dict):
        logger.debug(
            "run_query_expand: SLM output failed to parse; heuristic fallback. Raw: %r",
            raw_text[:300],
        )
        return _fallback_expand(query, "<parse-failed>", 0)

    raw_tokens = parsed.get("tokens") or []
    raw_apis = parsed.get("related_apis") or []
    raw_fts = parsed.get("fts_query") or ""
    rationale = parsed.get("rationale") or ""

    # Ground tokens
    tokens: list[str] = []
    for t in raw_tokens:
        if not isinstance(t, str):
            continue
        v = validate_token(t.strip())
        if v.ok:
            tokens.append(v.value)
        if len(tokens) >= max_tokens:
            break

    # Ground APIs
    apis: list[str] = []
    for a in raw_apis:
        if not isinstance(a, str):
            continue
        v = validate_api_name(a.strip())
        if v.ok:
            apis.append(v.value)
        if len(apis) >= 8:
            break

    # Ground fts_query
    fts = raw_fts.strip()
    fts_v = validate_fts_query(fts)
    if not fts_v.ok:
        # Build a fallback fts_query from the grounded tokens
        if tokens:
            fts = " OR ".join(tokens)
        else:
            fts = query.strip().lower()

    _, _, cfg = get_model()
    return ExpandedQuery(
        raw_query=query,
        tokens=tokens,
        related_apis=apis,
        fts_query=fts,
        rationale=str(rationale)[:200],
        model=cfg.model_id,
        latency_ms=latency_ms,
    )


def _fallback_expand(
    query: str, model: str, latency_ms: int
) -> ExpandedQuery:
    """Heuristic fallback: split query on whitespace, lowercase, validate."""
    tokens: list[str] = []
    for tok in query.split():
        cleaned = re.sub(r"[^a-z0-9_]", "", tok.lower())
        if cleaned:
            v = validate_token(cleaned)
            if v.ok:
                tokens.append(v.value)
    fts = " OR ".join(tokens) if tokens else query.strip().lower()
    return ExpandedQuery(
        raw_query=query,
        tokens=tokens,
        related_apis=[],
        fts_query=fts,
        rationale="fallback heuristic (SLM unavailable or output invalid)",
        model=model,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# 2. run_summarize
# ---------------------------------------------------------------------------


def run_summarize(
    *,
    binary_name: str,
    rva: str,
    body: str,
    style: str = "purpose",
    alias: str | None = None,
    callers: list[str] | None = None,
    callees: list[str] | None = None,
    known_symbols: set[str] | None = None,
    timeout_sec: int = 30,
) -> SummarizeResult:
    """Generate a 1-3 sentence summary of a decompiled function."""
    prompt = build_summarize_prompt(
        body=body,
        style=style,
        alias=alias,
        callers=callers,
        callees=callees,
    )
    raw_text, latency_ms = _invoke_slm(
        prompt, max_new_tokens=200, timeout_sec=timeout_sec
    )
    parsed = _extract_json(raw_text)
    if not isinstance(parsed, dict):
        # Fallback: take the raw text as the summary
        return SummarizeResult(
            summary=raw_text.strip()[:500] or "no summary available",
            subsystem_hint=None,
            binary_name=binary_name,
            rva=rva,
            style=style,
            model="<parse-failed>",
            latency_ms=latency_ms,
        )

    summary = (parsed.get("summary") or "").strip()
    sv = validate_summary(summary, known_symbols=known_symbols)
    if not sv.ok:
        # Fall back to a truncated version
        summary = summary[:500]
    subsystem = parsed.get("subsystem_hint")
    if not isinstance(subsystem, str) or not subsystem.strip():
        subsystem = None
    elif len(subsystem) > 60:
        subsystem = subsystem[:60]

    _, _, cfg = get_model()
    return SummarizeResult(
        summary=sv.cleaned or summary,
        subsystem_hint=subsystem,
        binary_name=binary_name,
        rva=rva,
        style=style,
        model=cfg.model_id,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# 3. run_suggest_name
# ---------------------------------------------------------------------------


def run_suggest_name(
    *,
    binary_name: str,
    rva: str,
    body: str,
    called_apis: list[str] | None = None,
    string_refs: list[str] | None = None,
    callers: list[str] | None = None,
    callees: list[str] | None = None,
    other_aliases: list[str] | None = None,
    timeout_sec: int = 30,
) -> SuggestNameResult:
    """Propose 1-3 candidate function names with confidence scores."""
    prompt = build_suggest_name_prompt(
        body=body,
        called_apis=called_apis,
        string_refs=string_refs,
        callers=callers,
        callees=callees,
        other_aliases=other_aliases,
    )
    raw_text, latency_ms = _invoke_slm(
        prompt, max_new_tokens=160, timeout_sec=timeout_sec
    )
    parsed = _extract_json(raw_text)
    if not isinstance(parsed, list):
        return SuggestNameResult(
            candidates=[],
            binary_name=binary_name,
            rva=rva,
            model="<parse-failed>",
            latency_ms=latency_ms,
        )

    candidates: list[NameCandidate] = []
    for item in parsed[:3]:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        conf = item.get("confidence")
        rationale = item.get("rationale", "")
        if not isinstance(name, str):
            continue
        v = validate_identifier(name.strip())
        if not v.ok:
            continue
        try:
            conf_f = float(conf) if conf is not None else 0.5
        except (TypeError, ValueError):
            conf_f = 0.5
        conf_f = max(0.0, min(1.0, conf_f))
        candidates.append(
            NameCandidate(
                name=v.value,
                confidence=conf_f,
                rationale=str(rationale)[:200],
            )
        )

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    _, _, cfg = get_model()
    return SuggestNameResult(
        candidates=candidates,
        binary_name=binary_name,
        rva=rva,
        model=cfg.model_id,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# 4. run_explain_callgraph
# ---------------------------------------------------------------------------


def run_explain_callgraph(
    *,
    binary_name: str,
    rva: str,
    target_name: str,
    body_excerpt: str,
    callers: list[str],
    callees: list[str],
    depth: int = 1,
    timeout_sec: int = 30,
) -> CallgraphExplanation:
    """2-3 sentence summary of a function in its call-graph neighborhood."""
    prompt = build_explain_callgraph_prompt(
        target_name=target_name,
        target_rva=rva,
        body_excerpt=body_excerpt,
        callers=callers,
        callees=callees,
    )
    raw_text, latency_ms = _invoke_slm(
        prompt, max_new_tokens=200, timeout_sec=timeout_sec
    )
    parsed = _extract_json(raw_text)
    if not isinstance(parsed, dict):
        return CallgraphExplanation(
            summary=raw_text.strip()[:400] or "no summary available",
            subsystem_hint=None,
            key_paths=[],
            binary_name=binary_name,
            rva=rva,
            depth=depth,
            model="<parse-failed>",
            latency_ms=latency_ms,
        )

    summary = (parsed.get("summary") or "").strip()[:400]
    subsystem = parsed.get("subsystem_hint")
    if not isinstance(subsystem, str) or not subsystem.strip():
        subsystem = None
    elif len(subsystem) > 60:
        subsystem = subsystem[:60]
    raw_paths = parsed.get("key_paths") or []
    if not isinstance(raw_paths, list):
        raw_paths = []
    key_paths: list[str] = []
    for p in raw_paths[:3]:
        if isinstance(p, str) and 0 < len(p) <= 200:
            key_paths.append(p)

    _, _, cfg = get_model()
    return CallgraphExplanation(
        summary=summary,
        subsystem_hint=subsystem,
        key_paths=key_paths,
        binary_name=binary_name,
        rva=rva,
        depth=depth,
        model=cfg.model_id,
        latency_ms=latency_ms,
    )
