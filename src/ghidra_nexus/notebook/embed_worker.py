"""Embed worker (Phase 3) — async background thread that drains embed_queue.

On every queue item, loads the artifact_views row, builds the embed text from
summary + key_entities, calls the embedder, and stores the resulting vector
in ``embeddings`` (meta) + ``vec_embeddings`` (vec0).

When all pending items are processed, marks ``vec_index_complete`` on the
binary and ``vec_status='ready'``.

This worker is optional — if sqlite-vec or the embedder is unavailable, the
queue accumulates rows but the worker does nothing, and ``vec_status`` stays
``fts_only``.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra_nexus.notebook.embedder import Embedder
    from ghidra_nexus.notebook.store import Notebook

logger = logging.getLogger(__name__)


class EmbedWorker:
    """Background embedder drain."""

    def __init__(self, nb: "Notebook", embedder: "Embedder"):
        self.nb = nb
        self.embedder = embedder
        self._thread: threading.Thread | None = None
        self._running = False
        self._total_processed = 0
        self._total_errors = 0

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        # Ensure vec0 table exists on the connection.
        from ghidra_nexus.notebook.vec import ensure_vec0_table

        ensure_vec0_table(self.nb.conn)
        self._thread = threading.Thread(target=self._run, name="embed-worker", daemon=True)
        self._thread.start()
        logger.info("embed worker started")

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=10)

    def _run(self) -> None:
        """Process queue items until stopped or queue is empty."""
        while self._running:
            # Load model lazily
            if not self.embedder.available:
                if not self.embedder.load():
                    logger.warning("embedder failed to load; worker idle")
                    time.sleep(30)
                    continue

            items = self.nb.embed_queue.pending()
            if not items:
                # Queue empty — check if we should mark binaries complete
                self._try_mark_complete()
                time.sleep(5)
                continue

            for item in items:
                if not self._running:
                    break
                try:
                    self._process_one(item)
                    self._total_processed += 1
                except Exception as e:
                    self._total_errors += 1
                    self.nb.embed_queue.mark_error(item["id"], str(e))
                    logger.debug("embed worker error on queue %d: %s", item["id"], e)

    def _process_one(self, item: dict) -> None:
        """Embed a single queue item."""
        src_view_id = item["src_view_id"]
        view_row = self.nb.conn.execute(
            "SELECT * FROM artifact_views WHERE id = ?", (src_view_id,)
        ).fetchone()
        if view_row is None:
            self.nb.embed_queue.mark_done(item["id"])
            return

        view = dict(view_row)
        binary_id = view["binary_id"]
        rva = view.get("rva") or ""
        kind = view["kind"]
        summary = view.get("summary") or ""

        import json

        entities = json.loads(view.get("key_entities") or "[]")
        entity_str = " ".join(f"{e.get('kind', '')}:{e.get('value', '')}" for e in entities)

        # Build embed text (same format as search_blob)
        text = f"{kind} @ {rva}\n{summary}\n{entity_str}"

        vec = self.embedder.encode(text)
        if vec is None:
            self.nb.embed_queue.mark_error(item["id"], "embedder returned None")
            return

        import struct

        vec_blob = struct.pack(f"<{len(vec)}f", *vec.astype("float32").flatten())

        # Insert meta row
        from ghidra_nexus.notebook.vec import EMBED_DIM, EMBED_MODEL_ID

        eid = self.nb.embeddings.insert(
            binary_id=binary_id,
            rva=rva,
            kind=kind,
            model=EMBED_MODEL_ID,
            dim=EMBED_DIM,
            embedder_version="sentence-transformers",
            src_view_id=src_view_id,
            analysis_generation=view.get("analysis_generation", 0),
            vec_blob=vec_blob,
        )

        # Insert into vec0
        from ghidra_nexus.notebook.vec import insert_vec

        insert_vec(self.nb.conn, rowid=eid, vec=vec, dim=EMBED_DIM)

        # Update embeddings row with vec_rowid link back
        self.nb.conn.execute(
            "UPDATE embeddings SET vec_rowid = ? WHERE id = ?", (eid, eid)
        )

        self.nb.embed_queue.mark_done(item["id"])
        logger.debug("embed worker processed view %d → embedding %d", src_view_id, eid)

    def _try_mark_complete(self) -> None:
        """If all embed_queue items are done/skipped/error, mark binaries complete."""
        # Check if there are ANY pending items
        pending = self.nb.conn.execute(
            "SELECT COUNT(*) FROM embed_queue WHERE status = 'pending'"
        ).fetchone()[0]
        if pending > 0:
            return

        # Mark each binary that has embeddings
        binaries = self.nb.binaries.all()
        from ghidra_nexus.notebook.vec import EMBED_MODEL_ID

        for b in binaries:
            embedded_count = self.nb.embeddings.count_for_binary(b["id"])
            views_count = self.nb.views.count_for_binary(b["id"])
            if views_count > 0 and embedded_count >= views_count:
                self.nb.binaries.set_vec_status(
                    b["name"],
                    vec_available=True,
                    model=EMBED_MODEL_ID,
                    index_complete=True,
                    progress=embedded_count,
                    target=views_count,
                )
