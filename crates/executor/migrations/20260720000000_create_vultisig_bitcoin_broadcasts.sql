-- Key-free Vultisig Bitcoin broadcast write-ahead state.
--
-- `submitting` is intentionally irreversible: it means network submission may
-- have happened. A restart must reconcile the exact stored bytes and must not
-- silently return the row to `prepared`. `finalized` is also terminal and may
-- be reached only from `accepted` while atomically recording the configured
-- observer's exact finality evidence.

CREATE TABLE vultisig_bitcoin_broadcasts (
    evidence_id BLOB PRIMARY KEY NOT NULL CHECK (length(evidence_id) = 32),
    target_id BLOB NOT NULL CHECK (length(target_id) = 32),
    finality_source_set_id BLOB NOT NULL CHECK (length(finality_source_set_id) = 32),
    minimum_finality_confirmations INTEGER NOT NULL
        CHECK (minimum_finality_confirmations BETWEEN 6 AND 4294967295),
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32),
    txid BLOB NOT NULL CHECK (length(txid) = 32),
    wtxid BLOB NOT NULL CHECK (length(wtxid) = 32),
    evidence_record BLOB NOT NULL,
    evidence_record_sha256 BLOB NOT NULL CHECK (length(evidence_record_sha256) = 32),
    tx_bytes BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'submitting', 'accepted', 'finalized')),
    finality_block_hash BLOB CHECK (finality_block_hash IS NULL OR length(finality_block_hash) = 32),
    finality_block_height INTEGER
        CHECK (finality_block_height IS NULL OR finality_block_height BETWEEN 0 AND 4294967295),
    finality_tip INTEGER
        CHECK (finality_tip IS NULL OR finality_tip BETWEEN 0 AND 4294967295),
    finality_confirmations INTEGER
        CHECK (finality_confirmations IS NULL OR finality_confirmations BETWEEN 6 AND 4294967295),
    finality_required_confirmations INTEGER
        CHECK (finality_required_confirmations IS NULL OR finality_required_confirmations BETWEEN 6 AND 4294967295),
    finality_evidence_hash BLOB
        CHECK (finality_evidence_hash IS NULL OR length(finality_evidence_hash) = 32),
    CHECK (
        (state = 'finalized'
            AND finality_block_hash IS NOT NULL
            AND finality_block_height IS NOT NULL
            AND finality_tip IS NOT NULL
            AND finality_confirmations IS NOT NULL
            AND finality_required_confirmations IS NOT NULL
            AND finality_evidence_hash IS NOT NULL)
        OR
        (state != 'finalized'
            AND finality_block_hash IS NULL
            AND finality_block_height IS NULL
            AND finality_tip IS NULL
            AND finality_confirmations IS NULL
            AND finality_required_confirmations IS NULL
            AND finality_evidence_hash IS NULL)
    )
);

CREATE INDEX idx_vultisig_bitcoin_broadcasts_target_state
    ON vultisig_bitcoin_broadcasts(
        target_id,
        finality_source_set_id,
        minimum_finality_confirmations,
        state,
        evidence_id
    );
