CREATE TABLE IF NOT EXISTS btc_finalized_inventory_state (
    inventory_id TEXT PRIMARY KEY NOT NULL,
    journal_id BLOB NOT NULL CHECK (length(journal_id) = 32),
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32),
    source_set_id BLOB NOT NULL CHECK (length(source_set_id) = 32),
    custody_script_pubkey BLOB NOT NULL,
    -- Must match ChainId::Btc.conf_depth() in xindex-shared.
    required_confirmations INTEGER NOT NULL CHECK (required_confirmations >= 6),
    observation_epoch INTEGER NOT NULL DEFAULT 0 CHECK (observation_epoch >= 0)
);

CREATE TABLE IF NOT EXISTS btc_finalized_inventory_blocks (
    inventory_id TEXT NOT NULL,
    block_height INTEGER NOT NULL CHECK (block_height >= 0),
    block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
    parent_hash BLOB NOT NULL CHECK (length(parent_hash) = 32),
    facts_hash BLOB NOT NULL CHECK (length(facts_hash) = 32),
    observation_evidence_hash BLOB NOT NULL
        CHECK (length(observation_evidence_hash) = 32),
    PRIMARY KEY (inventory_id, block_height),
    UNIQUE (inventory_id, block_hash),
    UNIQUE (inventory_id, block_height, block_hash),
    FOREIGN KEY (inventory_id)
        REFERENCES btc_finalized_inventory_state(inventory_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS btc_finalized_inventory_utxos (
    inventory_id TEXT NOT NULL,
    txid BLOB NOT NULL CHECK (length(txid) = 32),
    vout INTEGER NOT NULL CHECK (vout >= 0),
    value_sats INTEGER NOT NULL CHECK (value_sats > 0),
    script_pubkey BLOB NOT NULL,
    creation_height INTEGER NOT NULL CHECK (creation_height >= 0),
    creation_block_hash BLOB NOT NULL CHECK (length(creation_block_hash) = 32),
    spent_height INTEGER,
    spent_block_hash BLOB,
    PRIMARY KEY (inventory_id, txid, vout),
    FOREIGN KEY (inventory_id, creation_height, creation_block_hash)
        REFERENCES btc_finalized_inventory_blocks(
            inventory_id,
            block_height,
            block_hash
        )
        ON DELETE CASCADE,
    FOREIGN KEY (inventory_id, spent_height, spent_block_hash)
        REFERENCES btc_finalized_inventory_blocks(
            inventory_id,
            block_height,
            block_hash
        ),
    CHECK (
        (spent_height IS NULL AND spent_block_hash IS NULL)
        OR
        (spent_height IS NOT NULL AND spent_height >= creation_height
         AND length(spent_block_hash) = 32)
    )
);

CREATE INDEX IF NOT EXISTS idx_btc_finalized_inventory_unspent
    ON btc_finalized_inventory_utxos(inventory_id, spent_height, creation_height);
