-- Persistent state for the deadline-relayer's IntentTracker.
--
-- Closes Rust-audit finding L-R4 / M-R12: the in-memory `HashMap` lost
-- all tracked intents on daemon restart, requiring `--from-block`
-- backfill for recovery (safe via on-chain idempotency, but inefficient
-- and operationally noisy).
--
-- Schema is deliberately minimal — every column maps 1:1 to a field on
-- the `TrackedIntent` struct or is metadata for ops/debugging:
--
--   intent_id              32-byte event-derived id (primary key)
--   deadline_unix_secs     u64 from MintIntentCreated; cast to i64
--                          (SQLite INTEGER is i64; safe for timestamps
--                          well past year 9999)
--   index_token            20-byte address of the IndexToken clone
--                          that owns this intent
--   observed_at_unix_secs  wall-clock when we first saw the event;
--                          enables purging old rows during ops sweeps
--
-- Resolved intents are removed (DELETE), not soft-deleted — the table
-- is a worklist, not an audit log. On-chain events are the audit trail.

CREATE TABLE intents (
    intent_id BLOB PRIMARY KEY NOT NULL,
    deadline_unix_secs INTEGER NOT NULL,
    index_token BLOB NOT NULL,
    observed_at_unix_secs INTEGER NOT NULL
);

-- Used by the per-tick scan: WHERE deadline_unix_secs < ?.
CREATE INDEX idx_intents_deadline ON intents(deadline_unix_secs);
