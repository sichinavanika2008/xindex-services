-- H1 (audit 2026-06-01): reserve-before-broadcast write-ahead log.
--
-- The executor previously broadcast the Bitcoin tx BEFORE persisting the
-- idempotency row (`register`), and a `register` failure was swallowed
-- with only a `warn!`. A crash or transient SQLite error between the
-- irreversible broadcast and the record left NO row, so a `--from-block`
-- replay re-selected a different UTXO and broadcast a SECOND valid Asgard
-- deposit — the H-R1 double-pay, reopened through the ordering.
--
-- Fix: `BroadcastRegistry::reserve(intent_id)` writes a 'reserved' row
-- BEFORE the broadcast; `register` then promotes it to 'pending' with the
-- real txid/tx_bytes. A reserved-but-not-broadcast row (crash before
-- broadcast) is surfaced to the operator, never silently double-spent.
--
-- SQLite cannot ALTER a CHECK constraint, so recreate the table
-- preserving existing rows. The added 'reserved' status is excluded from
-- `list_pending` (the watcher only polls 'pending'), so a reserved
-- placeholder is never re-broadcast.

CREATE TABLE broadcasts_new (
    intent_id BLOB PRIMARY KEY NOT NULL,
    txid BLOB NOT NULL,
    tx_bytes BLOB NOT NULL,
    recipient_addr TEXT NOT NULL,
    amount_sats INTEGER NOT NULL,
    broadcast_at_unix_secs INTEGER NOT NULL,
    last_attempt_unix_secs INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'pending', 'confirmed', 'failed'))
);

INSERT INTO broadcasts_new
    SELECT intent_id, txid, tx_bytes, recipient_addr, amount_sats,
           broadcast_at_unix_secs, last_attempt_unix_secs, status
    FROM broadcasts;

DROP TABLE broadcasts;
ALTER TABLE broadcasts_new RENAME TO broadcasts;
CREATE INDEX idx_broadcasts_status ON broadcasts(status);
