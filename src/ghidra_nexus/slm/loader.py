"""GhidraNexus SLM module (Phase 6).

Opt-in 1-3B code-aware language model for RE agent tools. Off by default —
all tools return ``{"ok": false, "error_code": "slm_disabled", ...}`` when
``NEXUS_SLM_MODEL`` is unset.

Configuration (env vars):
    NEXUS_SLM_MODEL         HF model id (PyTorch OR ONNX-format).
                            Examples:
                              - "Qwen/Qwen2.5-Coder-1.5B-Instruct"  (PyTorch)
                              - "onnx-community/Qwen2.5-Coder-1.5B-Instruct"  (ONNX)
    NEXUS_SLM_FILE_NAME     ONNX file basename to load (e.g. "model_q4f16.onnx").
                            Default: auto-selects the smallest .onnx file in
                            the repo. Only meaningful for ONNX-format repos.
    NEXUS_SLM_DEVICE        "cpu" (default), "cuda", or "mps"
    NEXUS_SLM_QUANTIZE      "int8" or "int4" for memory-constrained PyTorch hosts
    NEXUS_SLM_MAX_TOKENS    per-call cap (default 256)
    NEXUS_SLM_TIMEOUT_SEC   per-call wall-clock cap (default 30)

Backend selection (automatic):
    - If the configured model resolves to a snapshot that contains an
      ``onnx/`` subfolder, we use ``optimum.onnxruntime.ORTModelForCausalLM``
      (CPU/CUDA via ONNX Runtime, ~3GB RAM for 1.5B INT4). Recommended.
    - Otherwise we use ``transformers.AutoModelForCausalLM`` (PyTorch).
      Heavier (~6GB RAM for 1.5B fp16) but works for any HF repo.

The model loads **lazily on first call** and is cached in module state for
the daemon's lifetime. Daemon startup is unaffected.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dependency probes (cheap, runs once at import)
# ---------------------------------------------------------------------------


def _try_import(name: str) -> tuple[bool, Any]:
    """Import a module by dotted name, returning (ok, module_or_None)."""
    try:
        import importlib

        module = importlib.import_module(name)
        return True, module
    except ImportError:
        return False, None


_HAS_TRANSFORMERS, transformers = _try_import("transformers")
_HAS_TORCH, torch = _try_import("torch")
_HAS_OPTIMUM, optimum = _try_import("optimum.onnxruntime")
_HAS_ONNXRUNTIME, onnxruntime = _try_import("onnxruntime")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SLMConfig:
    """Resolved configuration for an SLM session.

    All fields are read from env at first ``is_available()`` call and frozen
    so a single daemon run uses consistent settings across all 4 tools.
    """

    model_id: str
    file_name: str | None = None  # only meaningful for ONNX-format repos
    device: str = "cpu"
    quantize: str | None = None  # only meaningful for PyTorch
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

    file_name = os.environ.get("NEXUS_SLM_FILE_NAME") or None
    return SLMConfig(
        model_id=model_id,
        file_name=file_name,
        device=os.environ.get("NEXUS_SLM_DEVICE", "cpu"),
        quantize=os.environ.get("NEXUS_SLM_QUANTIZE") or None,
        max_tokens=_int_env("NEXUS_SLM_MAX_TOKENS", 256),
        timeout_sec=_int_env("NEXUS_SLM_TIMEOUT_SEC", 30),
    )


def _select_backend() -> str:
    """Choose the inference backend for the configured model.

    Returns:
        "onnx"      if the model resolves to an ONNX-format repo AND
                    optimum + onnxruntime are importable.
        "pytorch"   if transformers + torch are importable (always works
                    for any HF model; heavier memory footprint).
        "unavailable" if neither path is viable.

    The selection is determined once per daemon; :func:`is_available`
    reflects the result.
    """
    cfg = _read_config_from_env()
    if cfg is None:
        return "unavailable"

    if _is_onnx_format_repo(cfg.model_id):
        if _HAS_OPTIMUM and _HAS_ONNXRUNTIME:
            return "onnx"
        # Optimum not available — fall back to PyTorch if it can load
        # the underlying safetensors. ONNX-only repos don't have those,
        # so the loader will fail. That's correct behavior.

    if _HAS_TRANSFORMERS and _HAS_TORCH:
        return "pytorch"

    return "unavailable"


def _is_onnx_format_repo(model_id: str) -> bool:
    """Best-effort check: does this model resolve to an ONNX-format repo?

    Heuristic:
      - ``onnx-community/...`` is always ONNX.
      - Otherwise, try to peek at the HF file listing for an ``onnx/``
        subfolder. Network-free (cached).
    """
    if model_id.startswith("onnx-community/"):
        return True
    if not model_id:  # pragma: no cover
        return False
    try:
        from huggingface_hub import try_to_load_from_cache

        # Try to peek at any snapshot for an onnx/ subfolder marker.
        # If the model isn't cached at all, fall through to PyTorch.
        for subfolder in ("onnx/model.onnx", "onnx/model_q4f16.onnx",
                          "onnx/model_int8.onnx", "onnx/model_fp16.onnx",
                          "onnx/model_quantized.onnx"):
            try:
                path = try_to_load_from_cache(
                    model_id, subfolder, cache_dir=_hf_cache_dir()
                )
                if path is not None:
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False


def _hf_cache_dir() -> str | None:
    """Return HF_HOME if set, otherwise None (= use HF default)."""
    import os

    return os.environ.get("HF_HOME") or None


def is_available() -> bool:
    """True when ``NEXUS_SLM_MODEL`` is set AND a viable backend is installed.

    This does NOT load the model; use :func:`get_model` for that.
    """
    return _select_backend() != "unavailable"


def backend() -> str:
    """Which backend would be used for the current config.

    One of ``"onnx"``, ``"pytorch"``, ``"unavailable"``.
    """
    return _select_backend()


# ---------------------------------------------------------------------------
# Lazy-loaded model singleton
# ---------------------------------------------------------------------------

_MODEL_TOKENIZER: Any = None
_MODEL_INSTANCE: Any = None
_MODEL_CONFIG: SLMConfig | None = None
_MODEL_BACKEND: str | None = None
_MODEL_LOCK_NAME = "_slm_model_lock"  # documented for tests


def get_model() -> tuple[Any, Any, SLMConfig]:
    """Lazily load (tokenizer, model, config). Thread-safe via module lock.

    Raises:
        RuntimeError: when SLM is disabled (``NEXUS_SLM_MODEL`` unset) or the
            required dependencies are missing.

    The first call downloads/loads the model (3-15 seconds on CPU for ONNX,
    5-30 seconds for PyTorch). Subsequent calls return the cached instance.
    Call :func:`unload_model` on daemon shutdown to free ~1.5-6GB of RAM.
    """
    global _MODEL_TOKENIZER, _MODEL_INSTANCE, _MODEL_CONFIG, _MODEL_BACKEND

    if not is_available():
        raise RuntimeError(
            "SLM is disabled. Set NEXUS_SLM_MODEL=<hf_id> to enable."
        )

    if _MODEL_INSTANCE is not None:
        return _MODEL_TOKENIZER, _MODEL_INSTANCE, _MODEL_CONFIG  # type: ignore

    cfg = _read_config_from_env()
    assert cfg is not None  # is_available() just checked this
    backend_name = backend()

    if backend_name == "onnx":
        _MODEL_TOKENIZER, _MODEL_INSTANCE = _load_onnx(cfg)
    elif backend_name == "pytorch":
        _MODEL_TOKENIZER, _MODEL_INSTANCE = _load_pytorch(cfg)
    else:
        raise RuntimeError(
            f"No viable SLM backend for {cfg.model_id!r} (transformers/torch "
            "and optimum/onnxruntime both unavailable)"
        )

    _MODEL_CONFIG = cfg
    _MODEL_BACKEND = backend_name
    return _MODEL_TOKENIZER, _MODEL_INSTANCE, _MODEL_CONFIG


def _load_onnx(cfg: SLMConfig) -> tuple[Any, Any]:
    """Load an ONNX-format model via optimum + onnxruntime."""
    if not _HAS_OPTIMUM:  # pragma: no cover
        raise RuntimeError(
            "optimum is required to load ONNX-format models. "
            "Install with `uv add optimum[onnxruntime]`."
        )

    file_name = cfg.file_name
    if file_name is None:
        file_name = _auto_select_onnx_file(cfg.model_id)

    logger.info(
        "Loading ONNX SLM from %s (file=%s)...", cfg.model_id, file_name
    )
    tokenizer = transformers.AutoTokenizer.from_pretrained(  # type: ignore
        cfg.model_id,
        trust_remote_code=False,
    )
    # optimum's ORTModelForCausalLM with use_cache=False is the standard
    # for one-shot generation; KV-cache reuse across calls can be added
    # later if latency becomes a bottleneck.
    model = optimum.ORTModelForCausalLM.from_pretrained(  # type: ignore
        cfg.model_id,
        file_name=file_name,
        use_cache=False,
    )
    return tokenizer, model


def _auto_select_onnx_file(model_id: str) -> str:
    """Pick the smallest available .onnx file when the user didn't specify one.

    Preference order (smallest first):
      model_q4f16.onnx > model_int8.onnx > model_q4.onnx >
      model_quantized.onnx > model_uint8.onnx > model_fp16.onnx > model.onnx
    """
    import os

    preferred = [
        "model_q4f16.onnx",
        "model_int8.onnx",
        "model_q4.onnx",
        "model_quantized.onnx",
        "model_uint8.onnx",
        "model_fp16.onnx",
        "model.onnx",
    ]
    try:
        from huggingface_hub import try_to_load_from_cache, get_hf_file_metadata

        for fname in preferred:
            try:
                # First, check if it's locally cached
                local = try_to_load_from_cache(
                    model_id, f"onnx/{fname}", cache_dir=_hf_cache_dir()
                )
                if local is not None:
                    size_mb = os.path.getsize(local) / 1e6
                    logger.info("Auto-selected ONNX file %s (%.0f MB)", fname, size_mb)
                    return fname
                # Not cached — try to fetch metadata
                meta = get_hf_file_metadata(
                    f"{model_id}/onnx/{fname}", cache_dir=_hf_cache_dir()
                )
                size_mb = (meta.size or 0) / 1e6
                logger.info("Auto-selected ONNX file %s (%.0f MB)", fname, size_mb)
                return fname
            except Exception:
                continue
    except Exception:
        pass
    # Last resort: try the standard name
    return "model.onnx"


def _load_pytorch(cfg: SLMConfig) -> tuple[Any, Any]:
    """Load a PyTorch-format model via transformers."""
    if not _HAS_TRANSFORMERS or not _HAS_TORCH:  # pragma: no cover
        raise RuntimeError(
            "transformers + torch are required to load PyTorch-format models."
        )

    if cfg.device == "cpu":
        dtype = torch.float32
    else:
        dtype = torch.float16

    quant_cfg = None
    if cfg.quantize == "int8":
        from transformers import BitsAndBytesConfig
        quant_cfg = BitsAndBytesConfig(load_in_8bit=True)
    elif cfg.quantize == "int4":
        from transformers import BitsAndBytesConfig
        quant_cfg = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=dtype)

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
    return tokenizer, model


def unload_model() -> None:
    """Free SLM model resources. Safe to call multiple times."""
    global _MODEL_TOKENIZER, _MODEL_INSTANCE, _MODEL_CONFIG, _MODEL_BACKEND
    _MODEL_TOKENIZER = None
    _MODEL_INSTANCE = None
    _MODEL_CONFIG = None
    _MODEL_BACKEND = None


def model_status() -> dict:
    """Return a small status dict for the ``notebook_embed_status``-style tool.

    Reports whether the model is configured, loaded, and what backend.
    """
    cfg = _read_config_from_env()
    return {
        "available": is_available(),
        "configured": cfg is not None,
        "model_id": cfg.model_id if cfg else None,
        "file_name": cfg.file_name if cfg else None,
        "loaded": _MODEL_INSTANCE is not None,
        "backend": backend(),
        "device": cfg.device if cfg else None,
        "quantize": cfg.quantize if cfg else None,
        "has_transformers": _HAS_TRANSFORMERS,
        "has_torch": _HAS_TORCH,
        "has_optimum": _HAS_OPTIMUM,
        "has_onnxruntime": _HAS_ONNXRUNTIME,
    }
