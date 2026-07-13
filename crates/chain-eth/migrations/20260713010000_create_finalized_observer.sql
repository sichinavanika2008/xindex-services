CREATE TABLE IF NOT EXISTS evm_observer_blocks (
    observer_id TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
    parent_hash BLOB NOT NULL CHECK(length(parent_hash) = 32),
    header_evidence_hash BLOB NOT NULL CHECK(length(header_evidence_hash) = 32),
    logs_evidence_hash BLOB NOT NULL CHECK(length(logs_evidence_hash) = 32),
    processed_at INTEGER NOT NULL,
    PRIMARY KEY (observer_id, block_number)
);

CREATE TABLE IF NOT EXISTS evm_observer_legs (
    observer_id TEXT NOT NULL,
    dispatch_id BLOB NOT NULL CHECK(length(dispatch_id) = 32),
    redemption_id BLOB NOT NULL CHECK(length(redemption_id) = 32),
    leg_index INTEGER NOT NULL,
    target_token BLOB NOT NULL CHECK(length(target_token) = 20),
    amount BLOB NOT NULL CHECK(length(amount) = 32),
    memo BLOB NOT NULL,
    final_destination BLOB NOT NULL CHECK(length(final_destination) = 20),
    observed_at INTEGER NOT NULL,
    source_block INTEGER NOT NULL,
    source_block_hash BLOB NOT NULL CHECK(length(source_block_hash) = 32),
    source_transaction_hash BLOB NOT NULL CHECK(length(source_transaction_hash) = 32),
    source_transaction_index INTEGER NOT NULL,
    source_log_index INTEGER NOT NULL,
    PRIMARY KEY (observer_id, redemption_id, leg_index),
    UNIQUE (observer_id, dispatch_id),
    UNIQUE (observer_id, source_block, source_log_index)
);

CREATE TABLE IF NOT EXISTS evm_observer_mints (
    observer_id TEXT NOT NULL,
    intent_id BLOB NOT NULL CHECK(length(intent_id) = 32),
    slot_index INTEGER NOT NULL,
    slot_asset_id BLOB NOT NULL CHECK(length(slot_asset_id) = 32),
    slot_expected_amount BLOB NOT NULL CHECK(length(slot_expected_amount) = 32),
    index_token BLOB NOT NULL CHECK(length(index_token) = 20),
    originator BLOB NOT NULL CHECK(length(originator) = 20),
    funding_token BLOB NOT NULL CHECK(length(funding_token) = 20),
    amount_in BLOB NOT NULL CHECK(length(amount_in) = 32),
    deadline INTEGER NOT NULL,
    acquire_memo BLOB NOT NULL,
    acquire_vault BLOB NOT NULL CHECK(length(acquire_vault) = 20),
    observed_at INTEGER NOT NULL,
    source_block INTEGER NOT NULL,
    source_block_hash BLOB NOT NULL CHECK(length(source_block_hash) = 32),
    source_transaction_hash BLOB NOT NULL CHECK(length(source_transaction_hash) = 32),
    source_transaction_index INTEGER NOT NULL,
    intent_log_index INTEGER NOT NULL,
    acquire_log_index INTEGER NOT NULL,
    PRIMARY KEY (observer_id, intent_id, slot_index),
    UNIQUE (observer_id, source_block, intent_log_index),
    UNIQUE (observer_id, source_block, acquire_log_index)
);

CREATE TABLE IF NOT EXISTS evm_observer_cancels (
    observer_id TEXT NOT NULL,
    cancel_id BLOB NOT NULL CHECK(length(cancel_id) = 32),
    intent_id BLOB NOT NULL CHECK(length(intent_id) = 32),
    slot_index INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    source_block INTEGER NOT NULL,
    source_block_hash BLOB NOT NULL CHECK(length(source_block_hash) = 32),
    source_log_index INTEGER NOT NULL,
    PRIMARY KEY (observer_id, cancel_id),
    UNIQUE (observer_id, source_block, source_log_index)
);

CREATE INDEX IF NOT EXISTS idx_evm_observer_legs_source_block
    ON evm_observer_legs(observer_id, source_block);
CREATE INDEX IF NOT EXISTS idx_evm_observer_mints_source_block
    ON evm_observer_mints(observer_id, source_block);
CREATE INDEX IF NOT EXISTS idx_evm_observer_cancels_source_block
    ON evm_observer_cancels(observer_id, source_block);
