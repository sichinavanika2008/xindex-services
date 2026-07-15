-- Canonical finalized queue events consumed by the permissionless terminal
-- redemption worker. These rows share the observer block journal and are
-- deleted atomically with it during a verified finalized-chain rollback.
CREATE TABLE IF NOT EXISTS evm_observer_redemption_events (
    observer_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (
        event_kind IN ('created', 'leg_resolved', 'finalized', 'stuck_cancelled')
    ),
    redemption_id BLOB NOT NULL CHECK (length(redemption_id) = 32),
    index_token BLOB CHECK (index_token IS NULL OR length(index_token) = 20),
    deadline INTEGER,
    observed_at INTEGER NOT NULL,
    source_block INTEGER NOT NULL,
    source_block_hash BLOB NOT NULL CHECK (length(source_block_hash) = 32),
    source_transaction_hash BLOB NOT NULL CHECK (length(source_transaction_hash) = 32),
    source_transaction_index INTEGER NOT NULL,
    source_log_index INTEGER NOT NULL,
    PRIMARY KEY (observer_id, source_block, source_log_index),
    CHECK (
        (event_kind = 'created' AND index_token IS NOT NULL AND deadline IS NOT NULL)
        OR
        (event_kind != 'created' AND index_token IS NULL AND deadline IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_evm_observer_redemption_events_source
    ON evm_observer_redemption_events(observer_id, source_block, source_log_index);

CREATE INDEX IF NOT EXISTS idx_evm_observer_redemption_events_identity
    ON evm_observer_redemption_events(observer_id, redemption_id, event_kind);
