-- Persistent state for the redemption executor's broadcast registry.
--
-- Closes Rust-audit finding L-R2: prior `xindex-redeem` broadcast a
-- finalized Bitcoin transaction once and moved on. If the tx was
-- evicted from mempool (fee competition, reorg, network split) the
-- redemption silently lost — burnt shares on Ethereum, no BTC at the
-- user's address. This table is the work-list the watcher polls.
--
-- Lifecycle:
--   1. Executor signs + broadcasts tx; INSERT row with status='pending'.
--   2. Watcher polls Esplora `get_tx_status(txid)`:
--      - confirmed with sufficient depth → UPDATE status='confirmed'
--      - not seen + stuck-timeout exceeded → re-call broadcast(tx);
--        UPDATE last_attempt_unix_secs
--   3. Operator can sweep confirmed rows on a cron (`DELETE WHERE
--      status='confirmed' AND ...`); the table is a worklist, not an
--      audit log (on-chain RedeemSettled events are the audit trail).
--
-- Storing `tx_bytes` (consensus-encoded) is required for re-broadcast:
-- rebuilding the tx would risk picking a different UTXO if the multisig
-- has been spent from in the meantime, producing a different txid.

CREATE TABLE broadcasts (
    intent_id BLOB PRIMARY KEY NOT NULL,
    txid BLOB NOT NULL,
    tx_bytes BLOB NOT NULL,
    recipient_addr TEXT NOT NULL,
    amount_sats INTEGER NOT NULL,
    broadcast_at_unix_secs INTEGER NOT NULL,
    last_attempt_unix_secs INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'failed'))
);

-- The watcher walks pending broadcasts every tick. Index keeps the
-- O(pending) scan cheap even when the table accumulates historical
-- confirmed/failed rows.
CREATE INDEX idx_broadcasts_status ON broadcasts(status);
