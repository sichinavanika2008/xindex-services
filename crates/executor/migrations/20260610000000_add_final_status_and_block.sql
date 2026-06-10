-- M8 (audit 2026-06-01): deep-reorg re-validation of confirmed broadcasts.
--
-- The watcher previously marked a broadcast 'confirmed' once and stopped
-- polling it. A deep re-org that orphaned the confirming block was never
-- detected: the BTC payout vanished from the canonical chain while shares
-- stayed burnt on Ethereum, with no re-broadcast.
--
-- Fix: record the confirming block (block_hash + block_height) at
-- mark_confirmed time, keep re-validating 'confirmed' rows every watcher
-- tick, demote an orphaned row back to 'pending' (mark_pending) for
-- re-broadcast, and graduate a row that is buried `final_depth` deep to a
-- terminal 'final' status (so the re-validated set stays bounded). The
-- operator sweep contract moves from 'confirmed' to 'final'.
--
-- SQLite cannot ALTER a CHECK constraint nor add a column inside the same
-- step cleanly, so recreate the table preserving existing rows (block_hash
-- / block_height NULL for them; they are pending/confirmed-pre-M8 and will
-- be re-validated or re-confirmed on the next ticks).

CREATE TABLE broadcasts_new (
    intent_id BLOB PRIMARY KEY NOT NULL,
    txid BLOB NOT NULL,
    tx_bytes BLOB NOT NULL,
    recipient_addr TEXT NOT NULL,
    amount_sats INTEGER NOT NULL,
    broadcast_at_unix_secs INTEGER NOT NULL,
    last_attempt_unix_secs INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'pending', 'confirmed', 'final', 'failed')),
    -- The block the tx was last observed confirmed in. NULL unless status
    -- is 'confirmed'/'final'. The watcher compares block_hash against the
    -- chain's current block for the tx to detect a re-org.
    block_hash BLOB,
    block_height INTEGER
);

INSERT INTO broadcasts_new
    SELECT intent_id, txid, tx_bytes, recipient_addr, amount_sats,
           broadcast_at_unix_secs, last_attempt_unix_secs, status, NULL, NULL
    FROM broadcasts;

DROP TABLE broadcasts;
ALTER TABLE broadcasts_new RENAME TO broadcasts;
CREATE INDEX idx_broadcasts_status ON broadcasts(status);
