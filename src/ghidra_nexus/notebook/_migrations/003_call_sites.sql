-- 003_call_sites.sql
--
-- Hook-porting fidelity: cached call-site stack analysis per function.
-- One gzipped JSON blob per (binary_id, function entry rva, generation)
-- holding the full CallSiteAnalysisResult payload; MCP returns windows.

CREATE TABLE IF NOT EXISTS call_sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT NOT NULL,
    payload BLOB NOT NULL,                      -- gzipped JSON
    site_count INTEGER NOT NULL,
    analysis_generation INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS call_sites_binary_rva_idx
    ON call_sites(binary_id, rva, analysis_generation DESC);
CREATE UNIQUE INDEX IF NOT EXISTS call_sites_binary_rva_gen_idx
    ON call_sites(binary_id, rva, analysis_generation);
