CREATE TABLE IF NOT EXISTS posting_outbox_jobs (
    job_kind TEXT NOT NULL,
    identity BLOB NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
    payload BLOB NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 4194304),
    state TEXT NOT NULL CHECK (state IN ('queued', 'posting', 'posted', 'expired', 'superseded')),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL CHECK (next_attempt_at >= 0),
    last_error TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (job_kind, identity, generation)
);

CREATE UNIQUE INDEX IF NOT EXISTS posting_outbox_one_active_generation
    ON posting_outbox_jobs(job_kind, identity)
    WHERE state IN ('queued', 'posting');

CREATE INDEX IF NOT EXISTS posting_outbox_ready
    ON posting_outbox_jobs(job_kind, state, next_attempt_at, generation);

CREATE INDEX IF NOT EXISTS posting_outbox_history
    ON posting_outbox_jobs(job_kind, identity, generation, state);
