-- 001_initial.sql
--
-- GhidraNexus notebook foundation schema (Phase 1).
--
-- Cross-references:
--   F1  capability envelope (binaries.binary_class, reliability_notes)
--   F3  multi-binary project (binary_id FK on every per-binary row)
--   F5  address identity (binary_id, rva) composite PKs
--   F6  full blob in DB; offset/limit on the wire (not in schema)
--   F11 dual-format views (artifact_views.summary + key_entities JSON)
--   F12 sqlite-vec semantic index (embeddings meta + vec0 table created by vec.py when loadable)
--
-- PRAGMAs: applied by the migration runner, not embedded here, so the file
-- is portable across connection setups.

-- ---------------------------------------------------------------------------
-- binaries  (project-wide catalog)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    sha256 TEXT NOT NULL,
    image_base TEXT,                          -- e.g. '0x140000000'
    arch TEXT,                                -- 'x86_64' | 'x86' | 'arm64' | ...
    size_bytes INTEGER,
    function_count INTEGER NOT NULL DEFAULT 0,
    binary_class TEXT NOT NULL DEFAULT 'small',
    analysis_ready INTEGER NOT NULL DEFAULT 0,
    analysis_generation INTEGER NOT NULL DEFAULT 0,
    entropy_summary TEXT NOT NULL DEFAULT 'unknown',
    reliability_notes TEXT,                   -- JSON array of strings
    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_analyzed_at TIMESTAMP,
    -- F12 readiness surface (Phase 1 stores the columns; Phase 3 fills them)
    vec_index_complete INTEGER NOT NULL DEFAULT 0,
    embed_progress INTEGER NOT NULL DEFAULT 0,
    embed_target INTEGER NOT NULL DEFAULT 0,
    vec_status TEXT NOT NULL DEFAULT 'unavailable',
    embed_model TEXT
);
CREATE INDEX IF NOT EXISTS binaries_sha256_idx ON binaries(sha256);
CREATE INDEX IF NOT EXISTS binaries_class_idx ON binaries(binary_class);

-- ---------------------------------------------------------------------------
-- functions  (per-binary function inventory with quality flag)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS functions (
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT NOT NULL,                         -- PRIMARY address form (F5)
    name TEXT,
    size INTEGER,
    signature TEXT,
    quality TEXT NOT NULL DEFAULT 'unknown',  -- ok | stub | likely_encrypted | empty | unknown
    flags TEXT,                               -- JSON
    cached_decompile INTEGER,                 -- rowid into decompiles (set after put)
    cached_disasm INTEGER,                    -- rowid into disassemblies (set after put)
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (binary_id, rva)
);
CREATE INDEX IF NOT EXISTS functions_name_idx ON functions(name);
CREATE INDEX IF NOT EXISTS functions_binary_name_idx ON functions(binary_id, name);
CREATE INDEX IF NOT EXISTS functions_quality_idx ON functions(binary_id, quality);

-- ---------------------------------------------------------------------------
-- decompiles  (full gzip blob, generation-aware)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS decompiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT NOT NULL,
    code BLOB NOT NULL,                       -- gzipped text (Phase 1 sets this; readers must gunzip)
    lines INTEGER NOT NULL,
    warnings TEXT,                            -- JSON array
    source_hash TEXT,
    analysis_generation INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Latest generation wins per (binary_id, rva). Phase 2 inserts on miss;
-- Phase 5 may vacuum older generations.
CREATE INDEX IF NOT EXISTS decompiles_binary_rva_idx
    ON decompiles(binary_id, rva, analysis_generation DESC);
CREATE UNIQUE INDEX IF NOT EXISTS decompiles_binary_rva_gen_idx
    ON decompiles(binary_id, rva, analysis_generation);

-- ---------------------------------------------------------------------------
-- disassemblies
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS disassemblies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT NOT NULL,
    asm BLOB NOT NULL,
    instruction_count INTEGER NOT NULL,
    analysis_generation INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS disassemblies_binary_rva_idx
    ON disassemblies(binary_id, rva, analysis_generation DESC);
CREATE UNIQUE INDEX IF NOT EXISTS disassemblies_binary_rva_gen_idx
    ON disassemblies(binary_id, rva, analysis_generation);

-- ---------------------------------------------------------------------------
-- xrefs  (per-binary, multi-type)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS xrefs (
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    from_rva TEXT NOT NULL,
    to_rva TEXT NOT NULL,
    xref_type TEXT NOT NULL,                  -- code_call | code_jump | data_read | data_write | offset
    call_site TEXT,
    PRIMARY KEY (binary_id, from_rva, to_rva, xref_type)
);
CREATE INDEX IF NOT EXISTS xrefs_to_idx ON xrefs(binary_id, to_rva);
CREATE INDEX IF NOT EXISTS xrefs_from_idx ON xrefs(binary_id, from_rva);

-- ---------------------------------------------------------------------------
-- strings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS strings (
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT NOT NULL,
    text TEXT NOT NULL,
    encoding TEXT NOT NULL,                   -- ascii | utf16le | utf8
    length INTEGER NOT NULL,
    PRIMARY KEY (binary_id, rva, encoding)
);
CREATE INDEX IF NOT EXISTS strings_text_idx ON strings(text);

-- ---------------------------------------------------------------------------
-- breadcrumbs  (per-session tool-call audit trail)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS breadcrumbs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER REFERENCES binaries(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tool TEXT NOT NULL,
    args_hash TEXT,
    summary TEXT,
    rva TEXT,
    duration_ms INTEGER,
    truncated INTEGER DEFAULT 0,             -- 0/1
    error_code TEXT
);
CREATE INDEX IF NOT EXISTS breadcrumbs_session_ts_idx
    ON breadcrumbs(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS breadcrumbs_binary_idx
    ON breadcrumbs(binary_id, ts DESC);

-- ---------------------------------------------------------------------------
-- aliases  (per-binary address naming)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aliases (
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT NOT NULL,
    name TEXT NOT NULL,
    tags TEXT,                                -- JSON array
    status TEXT,                              -- hypothesis | confirmed | disproven
    confidence REAL,
    notes TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (binary_id, rva)
);
CREATE INDEX IF NOT EXISTS aliases_name_idx ON aliases(name);

-- ---------------------------------------------------------------------------
-- hypotheses  (project-wide reasoning board)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',      -- open | confirmed | disproven
    evidence_for TEXT,                        -- JSON array of {addr, note}
    evidence_against TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- artifact_views  (F11 dual-format: summary + key_entities JSON)
-- ---------------------------------------------------------------------------
-- This is the table FTS5 + sqlite-vec index against. We deliberately do not
-- store the raw blob here; raw lives in decompiles/disassemblies/etc. and the
-- F7 provenance chain (source_table, source_row_id, analysis_generation) lets
-- us pull it on demand when the agent actually expands a hit.
CREATE TABLE IF NOT EXISTS artifact_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT,
    kind TEXT NOT NULL,                       -- decompile | disasm | xrefs | strings | survey | section_health | ...
    source_table TEXT,                        -- 'decompiles' | 'disassemblies' | ...
    source_row_id INTEGER,
    summary TEXT NOT NULL,                    -- ≤ ~500 chars, deterministic
    key_entities TEXT NOT NULL,              -- JSON array of {kind, value, rva?}
    view_model TEXT NOT NULL DEFAULT 'extractive_v1',
    analysis_generation INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS artifact_views_binary_rva_kind_idx
    ON artifact_views(binary_id, rva, kind);
CREATE INDEX IF NOT EXISTS artifact_views_gen_idx
    ON artifact_views(binary_id, analysis_generation);
CREATE INDEX IF NOT EXISTS artifact_views_kind_idx
    ON artifact_views(kind);

-- ---------------------------------------------------------------------------
-- embeddings  (F12 meta rows; physical vec lives in vec0 or BLOB)
-- ---------------------------------------------------------------------------
-- If the vec0 extension is available, the actual float vector lives in a
-- companion table that vec.py creates at runtime. The meta row in this table
-- tracks model/dim/version and links to the source view.
CREATE TABLE IF NOT EXISTS embeddings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT,
    kind TEXT NOT NULL,                       -- mirrors artifact_views.kind
    model TEXT NOT NULL,                      -- 'all-MiniLM-L6-v2'
    dim INTEGER NOT NULL,                     -- 384
    embedder_version TEXT NOT NULL,          -- package/semver pin
    src_view_id INTEGER REFERENCES artifact_views(id) ON DELETE CASCADE,
    analysis_generation INTEGER NOT NULL DEFAULT 0,
    vec BLOB,                                -- float32 LE, len == dim*4; NULL if vec0 row only
    vec_rowid INTEGER,                       -- link into the vec0 virtual table
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS embeddings_binary_kind_idx ON embeddings(binary_id, kind);
CREATE INDEX IF NOT EXISTS embeddings_model_idx ON embeddings(model, dim);
CREATE UNIQUE INDEX IF NOT EXISTS embeddings_view_model_idx
    ON embeddings(src_view_id, model);

-- ---------------------------------------------------------------------------
-- embed_queue  (Phase 2 stub; Phase 3 worker drains it)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS embed_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_view_id INTEGER NOT NULL REFERENCES artifact_views(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | done | error | skipped
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS embed_queue_status_idx ON embed_queue(status, created_at);

-- ---------------------------------------------------------------------------
-- FTS5  (search index over distilled views, not raw)
-- ---------------------------------------------------------------------------
-- kind / binary_id / rva are UNINDEXED because we filter on them in WHERE
-- clauses and never tokenize them. body is the joined summary + entity
-- strings; name is the function/symbol name (high-value search hit).
CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
    kind UNINDEXED,
    binary_id UNINDEXED,
    rva UNINDEXED,
    name,
    body,
    tokenize = 'porter unicode61'
);

-- Schema for views: when an artifact_views row is inserted/updated, Phase 2
-- will issue the corresponding FTS upsert with body = summary + ' ' + ' '.join(
-- entity.value for entity in key_entities). Phase 1 only ships the empty
-- FTS table; Phase 2 wires the cache write-through.
