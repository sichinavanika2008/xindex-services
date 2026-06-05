-- C8 / Phase 4.6: widen the redemption_dispatch.chain CHECK constraint
-- to admit the TRON custody-family chain (tron) alongside the existing
-- 5 UTXO + 5 EVM + 1 Cosmos + 1 XRP + 1 Solana chains.
--
-- Same table-swap pattern as the Solana migration
-- (20260604000000_dispatch_solana_chains.sql): SQLite cannot ALTER a
-- CHECK in place, so create a v7 table with the widened CHECK, INSERT
-- SELECT every row + column verbatim, drop, rename. Schema is otherwise
-- identical; in-flight UTXO / EVM / Cosmos / XRP / Solana rows survive
-- bit-for-bit.

CREATE TABLE redemption_dispatch_v7 (
    redemption_id           BLOB    NOT NULL,
    leg_index               INTEGER NOT NULL DEFAULT 0,
    inbound_txid            TEXT    NOT NULL,
    dispatched_at_unix_secs INTEGER NOT NULL,
    chain                   TEXT    NOT NULL DEFAULT 'btc'
        CHECK(chain IN (
            'btc', 'ltc', 'bch', 'doge', 'zec',
            'eth', 'bsc', 'avax', 'base', 'pol',
            'gaia',
            'xrp',
            'sol',
            'tron'
        )),
    PRIMARY KEY (redemption_id, leg_index)
);

INSERT INTO redemption_dispatch_v7
    (redemption_id, leg_index, inbound_txid, dispatched_at_unix_secs, chain)
SELECT redemption_id, leg_index, inbound_txid, dispatched_at_unix_secs, chain
FROM redemption_dispatch;

DROP TABLE redemption_dispatch;

ALTER TABLE redemption_dispatch_v7 RENAME TO redemption_dispatch;
