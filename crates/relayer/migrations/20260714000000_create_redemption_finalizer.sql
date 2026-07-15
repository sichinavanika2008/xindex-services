-- Restart-safe mirror of one canonical finalized-observer journal plus the
-- durable permissionless finalizeBurn outbox derived from it.
CREATE TABLE IF NOT EXISTS redemption_finalizer_blocks (
    source_id TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
    parent_hash BLOB NOT NULL CHECK (length(parent_hash) = 32),
    header_evidence_hash BLOB NOT NULL CHECK (length(header_evidence_hash) = 32),
    logs_evidence_hash BLOB NOT NULL CHECK (length(logs_evidence_hash) = 32),
    processed_at INTEGER NOT NULL,
    PRIMARY KEY (source_id, block_number)
);

CREATE TABLE IF NOT EXISTS redemption_finalizer_events (
    source_id TEXT NOT NULL,
    source_block INTEGER NOT NULL,
    source_log_index INTEGER NOT NULL,
    event_kind TEXT NOT NULL CHECK (
        event_kind IN ('created', 'leg_resolved', 'finalized', 'stuck_cancelled')
    ),
    redemption_id BLOB NOT NULL CHECK (length(redemption_id) = 32),
    index_token BLOB CHECK (index_token IS NULL OR length(index_token) = 20),
    deadline INTEGER,
    PRIMARY KEY (source_id, source_block, source_log_index),
    CHECK (
        (event_kind = 'created' AND index_token IS NOT NULL AND deadline IS NOT NULL)
        OR
        (event_kind != 'created' AND index_token IS NULL AND deadline IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS redemption_finalizer_redemptions (
    source_id TEXT NOT NULL,
    redemption_id BLOB NOT NULL CHECK (length(redemption_id) = 32),
    index_token BLOB NOT NULL CHECK (length(index_token) = 20),
    deadline INTEGER NOT NULL,
    settlement_observed INTEGER NOT NULL DEFAULT 0 CHECK (settlement_observed IN (0, 1)),
    resolved INTEGER NOT NULL DEFAULT 0 CHECK (resolved IN (0, 1)),
    created_block INTEGER NOT NULL,
    created_log_index INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (source_id, redemption_id)
);

CREATE TABLE IF NOT EXISTS redemption_finalizer_jobs (
    source_id TEXT NOT NULL,
    redemption_id BLOB NOT NULL CHECK (length(redemption_id) = 32),
    index_token BLOB NOT NULL CHECK (length(index_token) = 20),
    state TEXT NOT NULL CHECK (state IN ('queued', 'posting', 'posted', 'superseded')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL CHECK (next_attempt_at >= 0),
    last_error TEXT,
    trigger_block INTEGER NOT NULL,
    trigger_log_index INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (source_id, redemption_id)
);

CREATE INDEX IF NOT EXISTS idx_redemption_finalizer_jobs_ready
    ON redemption_finalizer_jobs(source_id, state, next_attempt_at, trigger_block, trigger_log_index);

CREATE INDEX IF NOT EXISTS idx_redemption_finalizer_stuck
    ON redemption_finalizer_redemptions(source_id, resolved, settlement_observed, deadline);
