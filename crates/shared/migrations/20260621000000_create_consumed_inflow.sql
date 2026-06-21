-- RUST-004 (external AI audit 2026-06-20): consumed-inflow ledger.
--
-- The burn → USDT delivery cross-check confirms USDT landed at the GLOBAL
-- IndexToken address. Keyed only per (redemption_id, leg_index), two
-- redemptions could cite the SAME physical on-chain inflow → double-credit,
-- basket short one payout. This ledger binds each physical inflow
-- (transaction_hash, log_index) to the ONE redemption leg that consumed it,
-- so a second leg presenting the same inflow is refused.
--
-- Lives in the SAME sqlite DB as redemption_dispatch (REDEMPTION_DATABASE_URL):
-- both the executor and the redemption-attest binary point here, and the
-- same `sqlx::migrate!("./migrations")` set applies every table.
CREATE TABLE consumed_inflow (
    tx_hash       BLOB    NOT NULL,
    log_index     INTEGER NOT NULL,
    redemption_id BLOB    NOT NULL,
    leg_index     INTEGER NOT NULL,
    PRIMARY KEY (tx_hash, log_index)
);
