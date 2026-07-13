-- One-shot native-chain inflow ledger for mint deliveries and redemption
-- refunds. A physical UTXO may authorize exactly one logical lifecycle.
CREATE TABLE IF NOT EXISTS consumed_native_inflow (
    chain_id TEXT NOT NULL,
    tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
    output_index INTEGER NOT NULL,
    flow_kind TEXT NOT NULL CHECK(flow_kind IN ('mint_delivery', 'redemption_refund')),
    lifecycle_id BLOB NOT NULL CHECK(length(lifecycle_id) = 32),
    leg_index INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY (chain_id, tx_hash, output_index)
);

CREATE INDEX IF NOT EXISTS idx_consumed_native_lifecycle
    ON consumed_native_inflow(flow_kind, lifecycle_id, leg_index);
