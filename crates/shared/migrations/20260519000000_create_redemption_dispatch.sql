-- F2 correlation: redemptionId → the BTC→Asgard inbound the executor
-- broadcast, so the signer can exact-txid query THORChain. First-write
-- wins (re-broadcast must not change the correlated txid).
CREATE TABLE redemption_dispatch (
    redemption_id           BLOB    PRIMARY KEY NOT NULL,
    btc_txid                TEXT    NOT NULL,
    dispatched_at_unix_secs INTEGER NOT NULL
);
