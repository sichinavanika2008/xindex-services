-- V8 / Phase 3.2: widen the redemption_dispatch.chain CHECK constraint
-- to admit the 5 EVM custody-family chains (eth, bsc, avax, base, pol)
-- alongside the existing 5 UTXO chains (btc, ltc, bch, doge, zec).
--
-- SQLite cannot ALTER a CHECK constraint in place — use the table-swap
-- pattern from H1 (20260520000000_dispatch_per_leg.sql): create a v3
-- table with the widened CHECK, INSERT SELECT from the v2 table
-- preserving every row + every column verbatim, drop v2, rename v3.
--
-- Schema is otherwise identical: same PK (redemption_id, leg_index),
-- same column types/nullability, same `chain TEXT NOT NULL DEFAULT 'btc'`
-- shape. Existing in-flight UTXO rows survive bit-for-bit.

CREATE TABLE redemption_dispatch_v3 (
    redemption_id           BLOB    NOT NULL,
    leg_index               INTEGER NOT NULL DEFAULT 0,
    inbound_txid            TEXT    NOT NULL,
    dispatched_at_unix_secs INTEGER NOT NULL,
    chain                   TEXT    NOT NULL DEFAULT 'btc'
        CHECK(chain IN (
            'btc', 'ltc', 'bch', 'doge', 'zec',
            'eth', 'bsc', 'avax', 'base', 'pol'
        )),
    PRIMARY KEY (redemption_id, leg_index)
);

INSERT INTO redemption_dispatch_v3
    (redemption_id, leg_index, inbound_txid, dispatched_at_unix_secs, chain)
SELECT redemption_id, leg_index, inbound_txid, dispatched_at_unix_secs, chain
FROM redemption_dispatch;

DROP TABLE redemption_dispatch;

ALTER TABLE redemption_dispatch_v3 RENAME TO redemption_dispatch;
