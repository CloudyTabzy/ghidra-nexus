"""SLM module (Phase 6) — opt-in 1-3B local model for RE agent tools.

See :mod:`ghidra_nexus.slm.loader` for configuration. All four tools
(notebook_query_expand, notebook_summarize, notebook_suggest_name,
notebook_explain_callgraph) are gated on the ``NEXUS_SLM_MODEL`` env var.
"""
from ghidra_nexus.slm.loader import (
    SLMConfig,
    backend,
    get_model,
    is_available,
    model_status,
    unload_model,
)
from ghidra_nexus.slm.tasks import (
    CallgraphExplanation,
    ExpandedQuery,
    NameCandidate,
    SuggestNameResult,
    SummarizeResult,
    run_explain_callgraph,
    run_query_expand,
    run_suggest_name,
    run_summarize,
)

__all__ = [
    # Configuration / loader
    "SLMConfig",
    "backend",
    "get_model",
    "is_available",
    "model_status",
    "unload_model",
    # Result dataclasses
    "CallgraphExplanation",
    "ExpandedQuery",
    "NameCandidate",
    "SuggestNameResult",
    "SummarizeResult",
    # Task runners
    "run_explain_callgraph",
    "run_query_expand",
    "run_suggest_name",
    "run_summarize",
]
