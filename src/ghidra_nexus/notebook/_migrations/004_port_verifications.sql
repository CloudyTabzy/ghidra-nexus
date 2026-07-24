-- 004_port_verifications.sql
--
-- Hook-porting audit: every verify_port run is recorded so later sessions
-- recall prior verdicts (state-drift rule: surface the diff, not just the
-- latest answer). Rows are immutable; keyed by (binary_id, rva) per F13.

CREATE TABLE IF NOT EXISTS port_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    rva TEXT NOT NULL,                          -- target function entry RVA
    call_site_rva TEXT,                         -- set when verifying a call site
    signature TEXT NOT NULL,
    signature_hash TEXT NOT NULL,               -- sha256 of normalized signature
    verdict TEXT NOT NULL,                      -- pass | fail
    checks_json TEXT NOT NULL,                  -- JSON array of VerifyPortCheck
    warnings_json TEXT,                         -- JSON array of strings
    analysis_generation INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS port_verif_binary_rva_idx
    ON port_verifications(binary_id, rva, created_at DESC);
