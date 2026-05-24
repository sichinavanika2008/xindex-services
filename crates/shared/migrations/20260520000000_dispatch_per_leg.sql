-- H1 / Phase 3.0.1 hotfix: make redemption_dispatch per-leg keyed.
--
-- Phase 3.0 went per-leg on-chain (RedemptionLegRecord, per-leg
-- attestations) but the Rust mirror was keyed by redemption_id alone.
-- A multi-leg redemption's second leg's record_dispatch() hits
-- `INSERT OR IGNORE` on the redemption_id PK and is silently dropped,
-- so the signer can never correlate the second leg's inbound_txid.
-- This is a correctness bug latent today (single-async-slot rail) and
-- live in Phase 3.1 (mixed BTC + LTC + ... baskets).
--
-- Rename btc_txid → inbound_txid: under Phase 3.1 the inbound chain is
-- per-leg (not always BTC); the field name should not lie.
--
-- Backfill: every existing in-flight row is leg 0 (single-async-slot).
-- SQLite cannot alter PK in place — recreate the table, copy, swap.

CREATE TABLE redemption_dispatch_v2 (
    redemption_id           BLOB    NOT NULL,
    leg_index               INTEGER NOT NULL DEFAULT 0,
    inbound_txid            TEXT    NOT NULL,
    dispatched_at_unix_secs INTEGER NOT NULL,
    PRIMARY KEY (redemption_id, leg_index)
);

INSERT INTO redemption_dispatch_v2
    (redemption_id, leg_index, inbound_txid, dispatched_at_unix_secs)
SELECT redemption_id, 0, btc_txid, dispatched_at_unix_secs
FROM redemption_dispatch;

DROP TABLE redemption_dispatch;

ALTER TABLE redemption_dispatch_v2 RENAME TO redemption_dispatch;
