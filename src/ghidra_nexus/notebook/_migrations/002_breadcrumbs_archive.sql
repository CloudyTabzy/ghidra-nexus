-- 002_breadcrumbs_archive.sql
--
-- Phase 5 maintenance: long-term audit storage for breadcrumbs. Older
-- breadcrumbs are copied here before truncation so the agent retains a
-- searchable history without keeping the hot table unbounded.

CREATE TABLE IF NOT EXISTS breadcrumbs_archive (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_id INTEGER,
    binary_id INTEGER REFERENCES binaries(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    ts TIMESTAMP,
    tool TEXT NOT NULL,
    args_hash TEXT,
    summary TEXT,
    rva TEXT,
    duration_ms INTEGER,
    truncated INTEGER DEFAULT 0,
    error_code TEXT,
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS breadcrumbs_archive_session_idx
    ON breadcrumbs_archive(session_id, archived_at DESC);
CREATE INDEX IF NOT EXISTS breadcrumbs_archive_binary_idx
    ON breadcrumbs_archive(binary_id, archived_at DESC);
