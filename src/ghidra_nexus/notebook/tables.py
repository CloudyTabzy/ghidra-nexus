"""Sub-managers for every notebook table.

Each class in this module owns one SQLite table. Methods that write go through
``self.nb.transaction()``; methods that only read use ``self.nb.conn.execute``
directly so concurrent reads never block on the write lock.
"""

from __future__ import annotations

import gzip
import json
import logging
import sqlite3
import time
from typing import TYPE_CHECKING

from ghidra_nexus.notebook.pagination import clamp_limit, validate_offset, window_list
from ghidra_nexus.notebook.scale import classify_binary

if TYPE_CHECKING:
    from ghidra_nexus.notebook.store import Notebook

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# helpers shared by sub-managers
# ---------------------------------------------------------------------------

def _gz_compress(text: str) -> bytes:
    return gzip.compress(text.encode("utf-8"), compresslevel=6)


def _gz_decompress(blob: bytes) -> str:
    return gzip.decompress(blob).decode("utf-8")


def _json_serialize(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def _fts_index(
    nb: Notebook, *, kind: str, binary_id: int, rva: str, name: str, body: str
) -> None:
    """Best-effort FTS indexing for knowledge-plane writes.

    Never raises — a search-index failure must not fail the underlying write.
    """
    try:
        nb.search.upsert(kind=kind, binary_id=binary_id, rva=rva, name=name, body=body)
    except Exception:
        logger.warning("FTS indexing failed for %s @ %s", kind, rva, exc_info=True)


# ---------------------------------------------------------------------------
# binaries
# ---------------------------------------------------------------------------

class BinariesManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def upsert(
        self,
        *,
        name: str,
        sha256: str,
        image_base: str | None = None,
        arch: str | None = None,
        size_bytes: int | None = None,
        function_count: int | None = None,
    ) -> int:
        scale = classify_binary(size_bytes=size_bytes, function_count=function_count)
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO binaries (name, sha256, image_base, arch, size_bytes,
                   function_count, binary_class, reliability_notes, last_analyzed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(name) DO UPDATE SET
                   sha256 = excluded.sha256,
                   image_base = COALESCE(excluded.image_base, binaries.image_base),
                   arch = COALESCE(excluded.arch, binaries.arch),
                   size_bytes = COALESCE(excluded.size_bytes, binaries.size_bytes),
                   function_count = COALESCE(excluded.function_count, binaries.function_count),
                   binary_class = excluded.binary_class,
                   reliability_notes = excluded.reliability_notes,
                   last_analyzed_at = CURRENT_TIMESTAMP""",
                (
                    name,
                    sha256,
                    image_base,
                    arch,
                    size_bytes,
                    function_count or 0,
                    scale.binary_class,
                    _json_serialize(scale.reliability_notes),
                ),
            )
            row = conn.execute("SELECT id FROM binaries WHERE name = ?", (name,)).fetchone()
        assert row is not None
        return row[0]

    def get(self, name: str) -> dict | None:
        row = self.nb.conn.execute(
            "SELECT * FROM binaries WHERE name = ?", (name,)
        ).fetchone()
        return dict(row) if row else None

    def get_by_id(self, bid: int) -> dict | None:
        row = self.nb.conn.execute(
            "SELECT * FROM binaries WHERE id = ?", (bid,)
        ).fetchone()
        return dict(row) if row else None

    def all(self) -> list[dict]:
        return [
            dict(r)
            for r in self.nb.conn.execute("SELECT * FROM binaries ORDER BY name")
        ]

    def count(self) -> int:
        return self.nb.conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]

    def bump_generation(self, binary_name: str) -> int:
        with self.nb.transaction() as conn:
            conn.execute(
                "UPDATE binaries SET analysis_generation = analysis_generation + 1 WHERE name = ?",
                (binary_name,),
            )
            row = conn.execute(
                "SELECT analysis_generation FROM binaries WHERE name = ?", (binary_name,)
            ).fetchone()
        return row[0] if row else 0

    def mark_analysis_ready(
        self, binary_name: str, *, function_count: int | None = None
    ) -> None:
        with self.nb.transaction() as conn:
            if function_count is not None:
                conn.execute(
                    """UPDATE binaries SET
                       analysis_ready = 1,
                       function_count = ?,
                       last_analyzed_at = CURRENT_TIMESTAMP
                       WHERE name = ?""",
                    (function_count, binary_name),
                )
            else:
                conn.execute(
                    """UPDATE binaries SET
                       analysis_ready = 1,
                       last_analyzed_at = CURRENT_TIMESTAMP
                       WHERE name = ?""",
                    (binary_name,),
                )

    def set_vec_status(
        self,
        binary_name: str,
        *,
        vec_available: bool,
        model: str | None = None,
        index_complete: bool = False,
        progress: int | None = None,
        target: int | None = None,
    ) -> None:
        with self.nb.transaction() as conn:
            conn.execute(
                """UPDATE binaries SET
                   vec_status = ?,
                   vec_index_complete = ?,
                   embed_progress = ?,
                   embed_target = ?,
                   embed_model = ?
                   WHERE name = ?""",
                (
                    "ready" if (vec_available and index_complete) else ("fts_only" if not vec_available else "rebuilding"),
                    1 if index_complete else 0,
                    progress if progress is not None else 0,
                    target if target is not None else 0,
                    model,
                    binary_name,
                ),
            )


# ---------------------------------------------------------------------------
# functions
# ---------------------------------------------------------------------------

class FunctionsManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def upsert(
        self,
        *,
        binary_id: int,
        rva: str,
        name: str | None = None,
        size: int | None = None,
        signature: str | None = None,
        quality: str = "unknown",
        flags: dict | None = None,
    ) -> None:
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO functions (binary_id, rva, name, size, signature,
                   quality, flags, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                   ON CONFLICT(binary_id, rva) DO UPDATE SET
                   name = COALESCE(excluded.name, functions.name),
                   size = COALESCE(excluded.size, functions.size),
                   signature = COALESCE(excluded.signature, functions.signature),
                   quality = excluded.quality,
                   flags = COALESCE(excluded.flags, functions.flags),
                   last_seen = CURRENT_TIMESTAMP""",
                (binary_id, rva, name, size, signature, quality, _json_serialize(flags) if flags else None),
            )

    def get(self, binary_id: int, rva: str) -> dict | None:
        row = self.nb.conn.execute(
            "SELECT * FROM functions WHERE binary_id = ? AND rva = ?", (binary_id, rva)
        ).fetchone()
        return dict(row) if row else None

    def list(
        self, binary_id: int, *, offset: int = 0, limit: int = 0
    ) -> list[dict]:
        limit = clamp_limit("functions", limit) if limit else 100
        offset = validate_offset("functions", offset)
        return [
            dict(r)
            for r in self.nb.conn.execute(
                "SELECT * FROM functions WHERE binary_id = ? ORDER BY rva LIMIT ? OFFSET ?",
                (binary_id, limit, offset),
            )
        ]

    def count(self, binary_id: int) -> int:
        row = self.nb.conn.execute(
            "SELECT COUNT(*) FROM functions WHERE binary_id = ?", (binary_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def set_quality(self, binary_id: int, rva: str, quality: str) -> None:
        with self.nb.transaction() as conn:
            conn.execute(
                "UPDATE functions SET quality = ?, last_seen = CURRENT_TIMESTAMP WHERE binary_id = ? AND rva = ?",
                (quality, binary_id, rva),
            )


# ---------------------------------------------------------------------------
# decompiles
# ---------------------------------------------------------------------------

class DecompilesManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def put(
        self,
        *,
        binary_id: int,
        rva: str,
        code: str,
        lines: int,
        warnings: list | None = None,
        source_hash: str | None = None,
        analysis_generation: int = 0,
    ) -> int:
        blob = _gz_compress(code)
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO decompiles (binary_id, rva, code, lines, warnings,
                   source_hash, analysis_generation)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (binary_id, rva, blob, lines, _json_serialize(warnings) if warnings else None, source_hash, analysis_generation),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        return int(row[0]) if row else 0

    def get(self, binary_id: int, rva: str) -> dict | None:
        row = self.nb.conn.execute(
            """SELECT * FROM decompiles WHERE binary_id = ? AND rva = ?
               ORDER BY analysis_generation DESC LIMIT 1""",
            (binary_id, rva),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            result["code_text"] = _gz_decompress(result["code"])
        except Exception:
            result["code_text"] = ""
        return result

    def get_generation(self, binary_id: int, rva: str, gen: int) -> dict | None:
        row = self.nb.conn.execute(
            "SELECT * FROM decompiles WHERE binary_id = ? AND rva = ? AND analysis_generation = ?",
            (binary_id, rva, gen),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            result["code_text"] = _gz_decompress(result["code"])
        except Exception:
            result["code_text"] = ""
        return result

    def count_for_binary(self, binary_id: int) -> int:
        row = self.nb.conn.execute(
            "SELECT COUNT(*) FROM decompiles WHERE binary_id = ?", (binary_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def delete_old_generations(self, binary_id: int, keep_generations: int = 2) -> int:
        """Delete decompiles rows whose generation is older than the newest N."""
        if keep_generations < 1:
            keep_generations = 1
        with self.nb.transaction() as conn:
            before = conn.total_changes
            conn.execute(
                """DELETE FROM decompiles
                   WHERE binary_id = ?
                     AND analysis_generation < (
                         SELECT MIN(analysis_generation) FROM (
                             SELECT DISTINCT analysis_generation FROM decompiles
                             WHERE binary_id = ? ORDER BY analysis_generation DESC LIMIT ?
                         )
                     )""",
                (binary_id, binary_id, keep_generations),
            )
            return conn.total_changes - before


# ---------------------------------------------------------------------------
# disassemblies
# ---------------------------------------------------------------------------

class DisassembliesManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def put(
        self,
        *,
        binary_id: int,
        rva: str,
        asm: str,
        instruction_count: int,
        analysis_generation: int = 0,
    ) -> int:
        blob = _gz_compress(asm)
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO disassemblies (binary_id, rva, asm, instruction_count, analysis_generation)
                   VALUES (?, ?, ?, ?, ?)""",
                (binary_id, rva, blob, instruction_count, analysis_generation),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        return int(row[0]) if row else 0

    def get(self, binary_id: int, rva: str) -> dict | None:
        row = self.nb.conn.execute(
            """SELECT * FROM disassemblies WHERE binary_id = ? AND rva = ?
               ORDER BY analysis_generation DESC LIMIT 1""",
            (binary_id, rva),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            result["asm_text"] = _gz_decompress(result["asm"])
        except Exception:
            result["asm_text"] = ""
        return result

    def count_for_binary(self, binary_id: int) -> int:
        row = self.nb.conn.execute(
            "SELECT COUNT(*) FROM disassemblies WHERE binary_id = ?", (binary_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def delete_old_generations(self, binary_id: int, keep_generations: int = 2) -> int:
        """Delete disassembly rows whose generation is older than the newest N."""
        if keep_generations < 1:
            keep_generations = 1
        with self.nb.transaction() as conn:
            before = conn.total_changes
            conn.execute(
                """DELETE FROM disassemblies
                   WHERE binary_id = ?
                     AND analysis_generation < (
                         SELECT MIN(analysis_generation) FROM (
                             SELECT DISTINCT analysis_generation FROM disassemblies
                             WHERE binary_id = ? ORDER BY analysis_generation DESC LIMIT ?
                         )
                     )""",
                (binary_id, binary_id, keep_generations),
            )
            return conn.total_changes - before


# ---------------------------------------------------------------------------
# call_sites
# ---------------------------------------------------------------------------

class CallSitesManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def put(
        self,
        *,
        binary_id: int,
        rva: str,
        payload: str,
        site_count: int,
        analysis_generation: int = 0,
    ) -> int:
        blob = _gz_compress(payload)
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO call_sites (binary_id, rva, payload, site_count, analysis_generation)
                   VALUES (?, ?, ?, ?, ?)""",
                (binary_id, rva, blob, site_count, analysis_generation),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        return int(row[0]) if row else 0

    def get(self, binary_id: int, rva: str) -> dict | None:
        row = self.nb.conn.execute(
            """SELECT * FROM call_sites WHERE binary_id = ? AND rva = ?
               ORDER BY analysis_generation DESC LIMIT 1""",
            (binary_id, rva),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            result["payload_text"] = _gz_decompress(result["payload"])
        except Exception:
            result["payload_text"] = ""
        return result

    def count_for_binary(self, binary_id: int) -> int:
        row = self.nb.conn.execute(
            "SELECT COUNT(*) FROM call_sites WHERE binary_id = ?", (binary_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def delete_old_generations(self, binary_id: int, keep_generations: int = 2) -> int:
        """Delete call-site rows whose generation is older than the newest N."""
        if keep_generations < 1:
            keep_generations = 1
        with self.nb.transaction() as conn:
            before = conn.total_changes
            conn.execute(
                """DELETE FROM call_sites
                   WHERE binary_id = ?
                     AND analysis_generation < (
                         SELECT MIN(analysis_generation) FROM (
                             SELECT DISTINCT analysis_generation FROM call_sites
                             WHERE binary_id = ? ORDER BY analysis_generation DESC LIMIT ?
                         )
                     )""",
                (binary_id, binary_id, keep_generations),
            )
            return conn.total_changes - before


# ---------------------------------------------------------------------------
# port_verifications
# ---------------------------------------------------------------------------

class PortVerificationsManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def put(
        self,
        *,
        binary_id: int,
        rva: str,
        signature: str,
        signature_hash: str,
        verdict: str,
        checks: list[dict],
        warnings: list[str] | None = None,
        call_site_rva: str | None = None,
        analysis_generation: int = 0,
    ) -> int:
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO port_verifications
                   (binary_id, rva, call_site_rva, signature, signature_hash,
                    verdict, checks_json, warnings_json, analysis_generation)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    binary_id,
                    rva,
                    call_site_rva,
                    signature,
                    signature_hash,
                    verdict,
                    _json_serialize(checks),
                    _json_serialize(warnings) if warnings else None,
                    analysis_generation,
                ),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        check_names = " ".join(str(c.get("name", "")) for c in checks if isinstance(c, dict))
        _fts_index(
            self.nb,
            kind="port_verification",
            binary_id=binary_id,
            rva=rva,
            name=f"verify:{rva}",
            body=f"{signature} verdict={verdict} {check_names}",
        )
        return int(row[0]) if row else 0

    def latest_for(self, binary_id: int, rva: str) -> dict | None:
        row = self.nb.conn.execute(
            """SELECT * FROM port_verifications WHERE binary_id = ? AND rva = ?
               ORDER BY created_at DESC, id DESC LIMIT 1""",
            (binary_id, rva),
        ).fetchone()
        return dict(row) if row else None

    def list_for(self, binary_id: int, *, offset: int = 0, limit: int = 50) -> dict:
        limit = clamp_limit("breadcrumbs", limit)
        offset = validate_offset("breadcrumbs", offset)
        rows = self.nb.conn.execute(
            """SELECT * FROM port_verifications WHERE binary_id = ?
               ORDER BY created_at DESC, id DESC""",
            (binary_id,),
        ).fetchall()
        return window_list([dict(r) for r in rows], offset=offset, limit=limit)

    def count_for_binary(self, binary_id: int) -> int:
        row = self.nb.conn.execute(
            "SELECT COUNT(*) FROM port_verifications WHERE binary_id = ?", (binary_id,)
        ).fetchone()
        return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------

class XrefsManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def bulk_replace_for_target(
        self, binary_id: int, to_rva: str, refs: list[dict]
    ) -> None:
        with self.nb.transaction() as conn:
            conn.execute(
                "DELETE FROM xrefs WHERE binary_id = ? AND to_rva = ?",
                (binary_id, to_rva),
            )
            conn.executemany(
                "INSERT INTO xrefs (binary_id, from_rva, to_rva, xref_type, call_site) VALUES (?, ?, ?, ?, ?)",
                [
                    (binary_id, r["from_rva"], r["to_rva"], r["xref_type"], r.get("call_site"))
                    for r in refs
                ],
            )

    def list_to(self, binary_id: int, rva: str, *, offset: int = 0, limit: int = 50) -> dict:
        limit = clamp_limit("xrefs", limit)
        offset = validate_offset("xrefs", offset)
        rows = self.nb.conn.execute(
            "SELECT * FROM xrefs WHERE binary_id = ? AND to_rva = ?",
            (binary_id, rva),
        ).fetchall()
        return window_list([dict(r) for r in rows], offset=offset, limit=limit)

    def count_to(self, binary_id: int, rva: str) -> int:
        row = self.nb.conn.execute(
            "SELECT COUNT(*) FROM xrefs WHERE binary_id = ? AND to_rva = ?", (binary_id, rva)
        ).fetchone()
        return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------

class StringsManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def bulk_upsert(self, binary_id: int, strings: list[dict]) -> None:
        with self.nb.transaction() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO strings (binary_id, rva, text, encoding, length)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (binary_id, s["rva"], s["text"], s.get("encoding", "ascii"), s.get("length", len(s["text"])))
                    for s in strings
                ],
            )

    def search_like(
        self, binary_id: int, pattern: str, *, offset: int = 0, limit: int = 100
    ) -> dict:
        limit = clamp_limit("strings", limit)
        offset = validate_offset("strings", offset)
        rows = self.nb.conn.execute(
            "SELECT * FROM strings WHERE binary_id = ? AND text LIKE ?",
            (binary_id, f"%{pattern}%"),
        ).fetchall()
        return window_list([dict(r) for r in rows], offset=offset, limit=limit)


# ---------------------------------------------------------------------------
# breadcrumbs
# ---------------------------------------------------------------------------

class BreadcrumbsManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def insert(
        self,
        *,
        binary_id: int | None = None,
        session_id: str,
        tool: str,
        args_hash: str | None = None,
        summary: str = "",
        rva: str | None = None,
        duration_ms: int | None = None,
        truncated: bool = False,
        error_code: str | None = None,
    ) -> int:
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO breadcrumbs (binary_id, session_id, tool, args_hash,
                   summary, rva, duration_ms, truncated, error_code)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (binary_id, session_id, tool, args_hash, summary[:256], rva, duration_ms, 1 if truncated else 0, error_code),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        row_id = int(row[0]) if row else 0
        # Only failures are recall-worthy: full breadcrumb indexing would
        # flood FTS with near-identical auto-generated rows.
        if error_code:
            _fts_index(
                self.nb,
                kind="breadcrumb_error",
                binary_id=binary_id or 0,
                rva=rva or "",
                name=tool,
                body=f"{tool} failed with {error_code}: {summary[:256]}",
            )
        return row_id

    def recent(
        self,
        *,
        binary_id: int | None = None,
        session_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        limit = clamp_limit("breadcrumbs", limit)
        offset = validate_offset("breadcrumbs", offset)
        sql = "SELECT * FROM breadcrumbs WHERE 1=1"
        params: list = []
        if binary_id is not None:
            sql += " AND binary_id = ?"
            params.append(binary_id)
        if session_id is not None:
            sql += " AND session_id = ?"
            params.append(session_id)
        sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in self.nb.conn.execute(sql, params).fetchall()]

    def archive_old(
        self,
        *,
        binary_id: int | None = None,
        session_id: str | None = None,
        age_days: int = 30,
    ) -> dict:
        """Copy breadcrumbs older than ``age_days`` to archive, then delete them.

        Returns ``{"archived": int, "deleted": int}``. The archive table is
        created by migration 002; if it does not exist, this falls back to a
        plain delete and reports ``archived: 0``.
        """
        archived = 0
        deleted = 0
        cutoff = int(time.time()) - age_days * 86400

        # Build the candidate filter.
        where = "ts < datetime(?, 'unixepoch')"
        params: list = [cutoff]
        if binary_id is not None:
            where += " AND binary_id = ?"
            params.append(binary_id)
        if session_id is not None:
            where += " AND session_id = ?"
            params.append(session_id)

        with self.nb.transaction() as conn:
            # Best-effort archive copy. If the archive table is missing (very
            # old DB or manual schema change), just delete.
            try:
                before = conn.total_changes
                conn.execute(
                    f"""INSERT INTO breadcrumbs_archive
                        (original_id, binary_id, session_id, ts, tool, args_hash,
                         summary, rva, duration_ms, truncated, error_code)
                        SELECT id, binary_id, session_id, ts, tool, args_hash,
                               summary, rva, duration_ms, truncated, error_code
                        FROM breadcrumbs WHERE {where}""",
                    params,
                )
                archived = conn.total_changes - before
            except sqlite3.OperationalError as e:
                if "no such table" not in str(e).lower():
                    raise

            before = conn.total_changes
            conn.execute(f"DELETE FROM breadcrumbs WHERE {where}", params)
            deleted = conn.total_changes - before

        return {"archived": archived, "deleted": deleted}


# ---------------------------------------------------------------------------
# aliases
# ---------------------------------------------------------------------------

class AliasesManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def upsert(
        self,
        *,
        binary_id: int,
        rva: str,
        name: str,
        tags: list[str] | None = None,
        status: str | None = None,
        confidence: float | None = None,
        notes: str | None = None,
    ) -> None:
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO aliases (binary_id, rva, name, tags, status,
                   confidence, notes, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (binary_id, rva, name, _json_serialize(tags) if tags else None, status, confidence, notes),
            )
        body = " ".join([name, *(tags or []), notes or ""])
        _fts_index(self.nb, kind="alias", binary_id=binary_id, rva=rva, name=name, body=body)

    def get(self, binary_id: int, rva: str) -> dict | None:
        row = self.nb.conn.execute(
            "SELECT * FROM aliases WHERE binary_id = ? AND rva = ?", (binary_id, rva)
        ).fetchone()
        return dict(row) if row else None

    def list(self, binary_id: int) -> list[dict]:
        return [
            dict(r)
            for r in self.nb.conn.execute(
                "SELECT * FROM aliases WHERE binary_id = ? ORDER BY rva", (binary_id,)
            ).fetchall()
        ]


# ---------------------------------------------------------------------------
# hypotheses
# ---------------------------------------------------------------------------

class HypothesesManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def create(
        self,
        *,
        text: str,
        binary_id: int | None = None,
        status: str = "open",
        evidence_for: list | None = None,
        evidence_against: list | None = None,
    ) -> int:
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO hypotheses (binary_id, text, status, evidence_for, evidence_against)
                   VALUES (?, ?, ?, ?, ?)""",
                (binary_id, text, status, _json_serialize(evidence_for) if evidence_for else None, _json_serialize(evidence_against) if evidence_against else None),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        hid = int(row[0]) if row else 0
        _fts_index(
            self.nb,
            kind="hypothesis",
            binary_id=binary_id or 0,
            rva="",
            name=f"hypothesis:{hid}",
            body=f"{status}: {text}",
        )
        return hid

    def update(self, id_: int, **fields) -> None:
        sets = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values())
        values.append(id_)
        with self.nb.transaction() as conn:
            conn.execute(
                f"UPDATE hypotheses SET {sets}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                values,
            )
        row = self.get(id_)
        if row is not None:
            _fts_index(
                self.nb,
                kind="hypothesis",
                binary_id=row.get("binary_id") or 0,
                rva="",
                name=f"hypothesis:{id_}",
                body=f"{row.get('status', 'open')}: {row.get('text', '')}",
            )

    def list(self, *, binary_id: int | None = None, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM hypotheses WHERE 1=1"
        params: list = []
        if binary_id is not None:
            sql += " AND binary_id = ?"
            params.append(binary_id)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY updated_at DESC"
        return [dict(r) for r in self.nb.conn.execute(sql, params).fetchall()]

    def get(self, id_: int) -> dict | None:
        row = self.nb.conn.execute("SELECT * FROM hypotheses WHERE id = ?", (id_,)).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# artifact_views  (F11)
# ---------------------------------------------------------------------------

class ArtifactViewsManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def upsert(
        self,
        *,
        binary_id: int,
        rva: str | None,
        kind: str,
        source_table: str | None = None,
        source_row_id: int | None = None,
        summary: str,
        key_entities: str,
        view_model: str = "extractive_v1",
        analysis_generation: int = 0,
    ) -> int:
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO artifact_views (binary_id, rva, kind, source_table,
                   source_row_id, summary, key_entities, view_model, analysis_generation)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (binary_id, rva, kind, source_table, source_row_id, summary, key_entities, view_model, analysis_generation),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        return int(row[0]) if row else 0

    def get_for(self, binary_id: int, rva: str, kind: str) -> dict | None:
        row = self.nb.conn.execute(
            "SELECT * FROM artifact_views WHERE binary_id = ? AND rva = ? AND kind = ? ORDER BY analysis_generation DESC LIMIT 1",
            (binary_id, rva, kind),
        ).fetchone()
        return dict(row) if row else None

    def count_for_binary(self, binary_id: int) -> int:
        row = self.nb.conn.execute(
            "SELECT COUNT(*) FROM artifact_views WHERE binary_id = ?", (binary_id,)
        ).fetchone()
        return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# embeddings  (F12 meta)
# ---------------------------------------------------------------------------

class EmbeddingsManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def insert(
        self,
        *,
        binary_id: int,
        rva: str | None,
        kind: str,
        model: str,
        dim: int,
        embedder_version: str,
        src_view_id: int | None = None,
        analysis_generation: int = 0,
        vec_blob: bytes | None = None,
        vec_rowid: int | None = None,
    ) -> int:
        with self.nb.transaction() as conn:
            conn.execute(
                """INSERT INTO embeddings (binary_id, rva, kind, model, dim,
                   embedder_version, src_view_id, analysis_generation, vec, vec_rowid)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (binary_id, rva, kind, model, dim, embedder_version, src_view_id, analysis_generation, vec_blob, vec_rowid),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        return int(row[0]) if row else 0

    def delete_for_binary(self, binary_id: int) -> int:
        with self.nb.transaction() as conn:
            conn.execute("DELETE FROM embeddings WHERE binary_id = ?", (binary_id,))
            return conn.total_changes

    def count_for_binary(self, binary_id: int) -> int:
        row = self.nb.conn.execute(
            "SELECT COUNT(*) FROM embeddings WHERE binary_id = ?", (binary_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def list_for_binary(self, binary_id: int) -> list[dict]:
        return [
            dict(r)
            for r in self.nb.conn.execute(
                "SELECT * FROM embeddings WHERE binary_id = ?", (binary_id,)
            ).fetchall()
        ]


# ---------------------------------------------------------------------------
# embed_queue  (Phase 2 stub)
# ---------------------------------------------------------------------------

class EmbedQueueManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def enqueue(self, src_view_id: int) -> int:
        with self.nb.transaction() as conn:
            conn.execute(
                "INSERT INTO embed_queue (src_view_id, status) VALUES (?, 'pending')",
                (src_view_id,),
            )
            row = conn.execute("SELECT last_insert_rowid()").fetchone()
        return int(row[0]) if row else 0

    def pending(self) -> list[dict]:
        return [
            dict(r)
            for r in self.nb.conn.execute(
                "SELECT * FROM embed_queue WHERE status = 'pending' ORDER BY created_at"
            ).fetchall()
        ]

    def mark_done(self, queue_id: int) -> None:
        with self.nb.transaction() as conn:
            conn.execute(
                "UPDATE embed_queue SET status = 'done', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (queue_id,),
            )

    def mark_error(self, queue_id: int, error: str) -> None:
        with self.nb.transaction() as conn:
            conn.execute(
                "UPDATE embed_queue SET status = 'error', last_error = ?, attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (error, queue_id),
            )


# ---------------------------------------------------------------------------
# FTS search
# ---------------------------------------------------------------------------

class SearchManager:
    __slots__ = ("nb",)

    def __init__(self, nb: Notebook):
        self.nb = nb

    def query(
        self,
        fts_query: str,
        *,
        binary_id: int | None = None,
        kind: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        limit = clamp_limit("fts", limit if limit else 20)
        offset = validate_offset("fts", offset)
        # Escape FTS5 special characters to avoid syntax errors.
        safe = self._escape_fts(fts_query)
        sql = (
            "SELECT kind, binary_id, rva, name, snippet(fts, 4, '<b>', '</b>', '...', 32) AS snippet, rank "
            "FROM fts WHERE fts MATCH ?"
        )
        params: list = [safe]
        if binary_id is not None:
            sql += " AND binary_id = ?"
            params.append(binary_id)
        if kind is not None:
            sql += " AND kind = ?"
            params.append(kind)
        sql += " ORDER BY rank LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in self.nb.conn.execute(sql, params).fetchall()]

    def upsert(
        self,
        *,
        kind: str,
        binary_id: int,
        rva: str,
        name: str | None = None,
        body: str | None = None,
    ) -> None:
        """Insert or replace an FTS row keyed by (kind, binary_id, rva)."""
        with self.nb.transaction() as conn:
            # FTS5 doesn't support INSERT OR REPLACE directly over content-sync
            # tables. We use a delete+insert pair.
            conn.execute(
                "DELETE FROM fts WHERE kind = ? AND binary_id = ? AND rva = ?",
                (kind, binary_id, rva),
            )
            conn.execute(
                "INSERT INTO fts (kind, binary_id, rva, name, body) VALUES (?, ?, ?, ?, ?)",
                (kind, binary_id, rva, name or "", body or ""),
            )

    @staticmethod
    def _escape_fts(query: str) -> str:
        """Wrap FTS5-special characters in double quotes to avoid syntax errors.

        FTS5 treats ``*``, ``"``, ``(``, ``)``, ``:``, ``?``, and ``~`` specially.
        A bare query like ``malloc(`` would error. We wrap the whole query in
        double quotes if any of those characters appear, producing a phrase
        query that matches the literal token.
        """
        special = set("*\"():?~")
        if any(c in query for c in special):
            return f'"{query}"'
        return query

    def index_view(
        self,
        *,
        kind: str,
        binary_id: int,
        rva: str | None = None,
        name: str | None = None,
        body: str = "",
    ) -> None:
        """Shortcut: upsert an FTS row from extracted view data."""
        self.upsert(
            kind=kind,
            binary_id=binary_id,
            rva=rva or "",
            name=name,
            body=body,
        )
