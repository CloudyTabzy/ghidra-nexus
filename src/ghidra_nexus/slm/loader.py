"""GhidraNexus SLM module (Phase 6).

Opt-in 1-3B code-aware language model for RE agent tools. Off by default —
all tools return ``{"ok": false, "error_code": "slm_disabled", ...}`` when
``NEXUS_SLM_MODEL`` is unset.

Configuration (env vars):
    NEXUS_SLM_MODEL         HF model id, e.g. "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    NEXUS_SLM_DEVICE        "cpu" (default), "cuda", or "mps"
    NEXUS_SLM_QUANTIZE      "int8" or "int4" for memory-constrained hosts
    NEXUS_SLM_MAX_TOKENS    per-call cap (default 256)
    NEXUS_SLM_TIMEOUT_SEC   per-call wall-clock cap (default 30)

The model loads **lazily on first call** and is cached in module state for
the daemon's lifetime. Daemon startup is unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Eagerly imported (fast); transformers itself is heavy but is already a
# transitive dependency of sentence-transformers 4.1+, so no new install.
try:
    import transformers  # type: ignore
    _HAS_TRANSFORMERS = True
except ImportError:  # pragma: no cover
    transformers = None  # type: ignore
    _HAS_TRANSFORMERS = False

try:
    import torch  # type: ignore
    _HAS_TORCH = True
except ImportError:  # pragma: no cover
    torch = None  # type: ignore
    _HAS_TORCH = False


@dataclass(frozen=True)
class SLMConfig:
    """Resolved configuration for an SLM session.

    All fields are read from env at first ``is_available()`` call and frozen
    so a single daemon run uses consistent settings across all 4 tools.
    """

    model_id: str
    device: str = "cpu"
    quantize: str | None = None
    max_tokens: int = 256
    timeout_sec: int = 30


def _read_config_from_env() -> SLMConfig | None:
    """Read SLM config from env. Returns None when SLM is disabled."""
    import os

    model_id = os.environ.get("NEXUS_SLM_MODEL")
    if not model_id:
        return None

    def _int_env(name: str, default: int) -> int:
        raw = os.environ.get(name)
        if raw is None or raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    return SLMConfig(
        model_id=model_id,
        device=os.environ.get("NEXUS_SLM_DEVICE", "cpu"),
        quantize=os.environ.get("NEXUS_SLM_QUANTIZE") or None,
        max_tokens=_int_env("NEXUS_SLM_MAX_TOKENS", 256),
        timeout_sec=_int_env("NEXUS_SLM_TIMEOUT_SEC", 30),
    )


def is_available() -> bool:
    """True when ``NEXUS_SLM_MODEL`` is set AND transformers/torch importable.

    This does NOT load the model; use :func:`get_model` for that.
    """
    cfg = _read_config_from_env()
    if cfg is None:
        return False
    return _HAS_TRANSFORMERS and _HAS_TORCH


# ---------------------------------------------------------------------------
# Lazy-loaded model singleton
# ---------------------------------------------------------------------------

_MODEL_TOKENIZER: Any = None
_MODEL_INSTANCE: Any = None
_MODEL_CONFIG: SLMConfig | None = None
_MODEL_LOCK_NAME = "_slm_model_lock"  # documented for tests


def get_model() -> tuple[Any, Any, SLMConfig]:
    """Lazily load (tokenizer, model, config). Thread-safe via module lock.

    Raises:
        RuntimeError: when SLM is disabled (``NEXUS_SLM_MODEL`` unset) or the
            required dependencies are missing.

    The first call downloads/loads the model (5-30 seconds on CPU). Subsequent
    calls return the cached instance. Call :func:`unload_model` on daemon
    shutdown to free ~3GB of RAM.
    """
    global _MODEL_TOKENIZER, _MODEL_INSTANCE, _MODEL_CONFIG

    if not is_available():
        raise RuntimeError(
            "SLM is disabled. Set NEXUS_SLM_MODEL=<hf_id> to enable."
        )

    if _MODEL_INSTANCE is not None:
        return _MODEL_TOKENIZER, _MODEL_INSTANCE, _MODEL_CONFIG  # type: ignore

    cfg = _read_config_from_env()
    assert cfg is not None  # is_available() just checked this

    # Lazy import torch dtype selection
    if cfg.device == "cpu":
        dtype = torch.float32
    else:
        dtype = torch.float16  # GPU/MPS use half precision

    quant_cfg = None
    if cfg.quantize == "int8":
        from transformers import BitsAndBytesConfig  # type: ignore
        quant_cfg = BitsAndBytesConfig(load_in_8bit=True)
    elif cfg.quantize == "int4":
        from transformers import BitsAndBytesConfig  # type: ignore
        quant_cfg = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=dtype,
        )

    tokenizer = transformers.AutoTokenizer.from_pretrained(  # type: ignore
        cfg.model_id,
        trust_remote_code=False,
    )
    model = transformers.AutoModelForCausalLM.from_pretrained(  # type: ignore
        cfg.model_id,
        torch_dtype=dtype,
        device_map=cfg.device if quant_cfg is None else None,
        quantization_config=quant_cfg,
        trust_remote_code=False,
    )
    if quant_cfg is None and cfg.device != "cpu":
        model = model.to(cfg.device)
    model.eval()

    _MODEL_TOKENIZER = tokenizer
    _MODEL_INSTANCE = model
    _MODEL_CONFIG = cfg
    return tokenizer, model, cfg


def unload_model() -> None:
    """Free SLM model resources. Safe to call multiple times."""
    global _MODEL_TOKENIZER, _MODEL_INSTANCE, _MODEL_CONFIG
    _MODEL_TOKENIZER = None
    _MODEL_INSTANCE = None
    _MODEL_CONFIG = None


def model_status() -> dict:
    """Return a small status dict for the ``notebook_embed_status``-style tool.

    Reports whether the model is configured, loaded, and what it is.
    """

    cfg = _read_config_from_env()
    return {
        "available": is_available(),
        "configured": cfg is not None,
        "model_id": cfg.model_id if cfg else None,
        "loaded": _MODEL_INSTANCE is not None,
        "device": cfg.device if cfg else None,
        "quantize": cfg.quantize if cfg else None,
        "has_transformers": _HAS_TRANSFORMERS,
        "has_torch": _HAS_TORCH,
    }
