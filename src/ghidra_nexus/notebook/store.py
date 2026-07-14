"""Notebook store: SQLite connection, migrations, and the public ``Notebook`` class.

The :class:`Notebook` is the Python API the MCP tools and CLI both consume.
It owns one SQLite connection per project and exposes sub-managers:

- :attr:`Notebook.binaries`      — catalog + scale + generation
- :attr:`Notebook.functions`     — per-binary function inventory with quality
- :attr:`Notebook.decompiles`    — gzipped decompiles, generation-aware
- :attr:`Notebook.disassemblies` — gzipped disasm listings
- :attr:`Notebook.xrefs`         — cross-references
- :attr:`Notebook.strings`       — string inventory
- :attr:`Notebook.breadcrumbs`   — session audit trail
- :attr:`Notebook.aliases`       — address names + tags
- :attr:`Notebook.hypotheses`    — project-wide hypothesis board
- :attr:`Notebook.views`         — dual-format F11 views
- :attr:`Notebook.embeddings`    — F12 metadata rows
- :attr:`Notebook.embed_queue`   — pending embeddings
- :attr:`Notebook.search`        — FTS5 helpers

Sub-managers live in :mod:`ghidra_nexus.notebook.tables`. This file holds the
:class:`Notebook` class itself, the connection management, and the migration
runner.

Concurrency model:
- One :class:`Notebook` per project. Multiple tools share the same connection.
- WAL + ``busy_timeout=5000`` allows concurrent reads + one writer.
- Writes go through short ``BEGIN IMMEDIATE`` transactions inside sub-managers.
- The :class:`Notebook` is *not* thread-safe to instantiate from multiple
  threads (each thread should call :meth:`open`); but it is safe to share
  between MCP handler coroutines because asyncio hands off control between
  awaits and a single ``sqlite3.Connection`` is fine for that.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ghidra_nexus.notebook import tables
from ghidra_nexus.notebook.scale import classify_binary
from ghidra_nexus.notebook.vec import VecStatus, try_enable_vec


logger = logging.getLogger(__name__)


MIGRATIONS_DIR = Path(__file__).parent / "_migrations"
SCHEMA_VERSION = 2


@dataclass
class NotebookConfig:
    """Configuration for :meth:`Notebook.open`."""

    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)


class Notebook:
    """Public API: SQLite-backed knowledge plane for one project."""

    def __init__(self, cfg: NotebookConfig, *, _conn: sqlite3.Connection | None = None):
        self.cfg = cfg
        # When tests inject a connection we don't manage its lifecycle.
        self._owns_conn = _conn is None
        self._conn = _conn or sqlite3.connect(
            str(cfg.path),
            isolation_level=None,           # autocommit; we manage txns explicitly
            check_same_thread=False,        # multi-thread fine when we lock writes
            timeout=30.0,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        # Write lock must exist before _migrate() because migrate uses
        # self.transaction() which acquires the lock.
        self._write_lock = threading.RLock()
        self._migrate()
        self._vec_status = try_enable_vec(self._conn)
        if self._vec_status.available:
            logger.info(
                "sqlite-vec loaded (model=%s dim=%d)",
                self._vec_status.model_default,
                self._vec_status.dim,
            )
        else:
            logger.warning(
                "sqlite-vec unavailable — FTS-only mode (%s)",
                self._vec_status.error or "no detail",
            )

        # Sub-managers — built lazily so the test suite can poke the underlying
        # connection without triggering the table-creation migration twice.
        self._submanagers_ready = False
        self.binaries = tables.BinariesManager(self)
        self.functions = tables.FunctionsManager(self)
        self.decompiles = tables.DecompilesManager(self)
        self.disassemblies = tables.DisassembliesManager(self)
        self.xrefs = tables.XrefsManager(self)
        self.strings = tables.StringsManager(self)
        self.breadcrumbs = tables.BreadcrumbsManager(self)
        self.aliases = tables.AliasesManager(self)
        self.hypotheses = tables.HypothesesManager(self)
        self.views = tables.ArtifactViewsManager(self)
        self.embeddings = tables.EmbeddingsManager(self)
        self.embed_queue = tables.EmbedQueueManager(self)
        self.search = tables.SearchManager(self)
        self._submanagers_ready = True

    # ----- lifecycle ------------------------------------------------------

    @classmethod
    def open(cls, path: str | Path) -> "Notebook":
        """Open or create a notebook at ``path``.

        Idempotent: a fresh DB migrates to the latest schema; an existing DB
        opens with whatever ``PRAGMA user_version`` it has (never downgrades).
        """
        cfg = NotebookConfig(path=Path(path))
        return cls(cfg)

    def close(self) -> None:
        if self._owns_conn:
            try:
                self._conn.close()
            except Exception:
                logger.warning("Notebook.close: connection close failed", exc_info=True)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Short, single-statement-at-a-time BEGIN IMMEDIATE/ROLLBACK context.

        Sub-managers use this internally. Tests can use it too but the public
        API is intentionally narrow — prefer a sub-manager method over raw SQL.
        """
        with self._write_lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    @property
    def conn(self) -> sqlite3.Connection:
        """Raw connection (read-only preferred; use :meth:`transaction` for writes)."""
        return self._conn

    @property
    def vec_status(self) -> VecStatus:
        return self._vec_status

    @property
    def vec_available(self) -> bool:
        return self._vec_status.available

    # ----- migrations ------------------------------------------------------

    def _migrate(self) -> None:
        """Apply pending migrations via PRAGMA user_version bookkeeping.

        ``executescript`` handles its own transactional boundaries (the migration
        SQL may contain ``COMMIT`` for pragma changes), so we don't wrap in an
        outer transaction.
        """
        cur = self._conn.execute("PRAGMA user_version")
        current = cur.fetchone()[0]
        while current < SCHEMA_VERSION:
            migration_files = sorted(MIGRATIONS_DIR.glob(f"{current + 1:03d}_*.sql"))
            if not migration_files:
                raise RuntimeError(
                    f"missing migration file {current + 1:03d}_*.sql in {MIGRATIONS_DIR}"
                )
            sql_path = migration_files[0]
            if len(migration_files) > 1:
                raise RuntimeError(
                    f"multiple migration files for version {current + 1}: {migration_files}"
                )
            sql = sql_path.read_text(encoding="utf-8")
            with self._write_lock:
                self._conn.executescript(sql)
                self._conn.execute(f"PRAGMA user_version = {current + 1}")
            current += 1
            logger.info("notebook migration applied: %s", sql_path.name)

    # ----- convenience -----------------------------------------------------

    def __repr__(self) -> str:
        return f"<Notebook path={self.cfg.path} user_version={self._user_version()} vec_available={self.vec_available}>"

    def _user_version(self) -> int:
        return self._conn.execute("PRAGMA user_version").fetchone()[0]

    def close_quietly(self) -> None:
        """Variant for tests that always succeed."""
        try:
            self.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helpers used by sub-managers
# ---------------------------------------------------------------------------

def _json_or_none(value: object) -> str | None:
    """JSON-encode ``value`` if not None; return None otherwise."""
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, default=str)


def _notes_json(notes: list[str]) -> str:
    return json.dumps(notes, ensure_ascii=False)
