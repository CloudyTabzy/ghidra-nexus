"""MiniLM embedder (F12) — text → 384-d float32 vectors via sentence-transformers.

Loads lazily on first ``encode()`` call so the daemon starts instantly. If the
model or backend is unavailable, ``available`` stays False and ``encode()``
returns ``None`` — the caller degrades to FTS-only.

Phase 3 uses this in the embed_worker to process embed_queue rows. Phase 5 adds
model version validation on rebuild.
"""

from __future__ import annotations

import logging
import threading
from typing import Final

import numpy as np

logger = logging.getLogger(__name__)

EMBED_MODEL_ID: Final[str] = "all-MiniLM-L6-v2"
EMBED_DIM: Final[int] = 384


class Embedder:
    """Lazy-loaded MiniLM embedder.

    Thread-safe: ``_load_lock`` serialises the one-time model load. Subsequent
    ``encode()`` calls share the loaded model without locking.
    """

    def __init__(
        self,
        model_id: str = EMBED_MODEL_ID,
        dim: int = EMBED_DIM,
    ):
        self.model_id = model_id
        self.dim = dim
        self._model: object | None = None
        self._lock = threading.Lock()
        self._error: str | None = None

    @property
    def available(self) -> bool:
        return self._model is not None and self._error is None

    def load(self) -> bool:
        """Attempt to load the model. Returns True on success."""
        if self._model is not None:
            return True
        with self._lock:
            if self._model is not None:
                return True
            try:
                from sentence_transformers import SentenceTransformer  # type: ignore

                logger.info("loading embedder model %s ...", self.model_id)
                self._model = SentenceTransformer(self.model_id, trust_remote_code=False)
                logger.info("embedder %s loaded (dim=%d)", self.model_id, self.dim)
                return True
            except Exception as e:
                self._error = str(e)
                logger.warning("embedder %s failed to load: %s", self.model_id, e)
                return False

    def encode(self, text: str) -> np.ndarray | None:
        """Return a ``float32[dim]`` vector, or None on failure."""
        if not self.load():
            return None
        if not text or not text.strip():
            return np.zeros(self.dim, dtype=np.float32)
        try:
            vec = self._model.encode(  # type: ignore
                [text],
                batch_size=1,
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,  # cosine → normalized
            )
            return vec[0].astype(np.float32)
        except Exception as e:
            logger.warning("embedder encode failed: %s", e)
            return None

    def encode_batch(self, texts: list[str]) -> np.ndarray | None:
        """Return ``float32[N, dim]`` or None."""
        if not self.load():
            return None
        valid = [t for t in texts if t and t.strip()]
        if not valid:
            return np.zeros((len(texts), self.dim), dtype=np.float32)
        try:
            vecs = self._model.encode(  # type: ignore
                valid,
                batch_size=min(32, len(valid)),
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,
            )
            return vecs.astype(np.float32)
        except Exception as e:
            logger.warning("embedder encode_batch failed: %s", e)
            return None

    def status(self) -> dict:
        return {
            "model_id": self.model_id,
            "dim": self.dim,
            "available": self.available,
            "error": self._error,
            "embedder_version": "sentence-transformers",
        }


# Module-level shared instance, loaded lazily.
_default_embedder: Embedder | None = None


def get_embedder() -> Embedder:
    global _default_embedder
    if _default_embedder is None:
        _default_embedder = Embedder()
    return _default_embedder


def reset_embedder() -> None:
    global _default_embedder
    _default_embedder = None
