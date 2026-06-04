-- Phase 4.5 S5: crash-recovery state for the Solana (Squads V4) redeem leg.
--
-- A Squads redemption broadcasts 1 + threshold + 1 separate on-chain
-- transactions. Two pieces of state MUST survive a mid-flight restart so
-- the leg never double-spends:
--
-- 1. redemption_id -> transaction_index. Allocated ONCE, write-ahead,
--    before the first broadcast. Re-deriving the index from chain state on
--    resume could pick a different index and create a second proposal that
--    also pays the user. The PRIMARY KEY + INSERT-OR-IGNORE make the
--    allocation atomic.
-- 2. The per-step signer cache (the 2h signerCacheExpiry defense): within
--    2h of a broadcast a step is never re-signed; after expiry it is
--    re-signed only if an on-chain lookup confirms the tx did NOT land.
--
-- Step progress itself is derived from the on-chain proposal account, not
-- from local state — the chain is the witness.

CREATE TABLE solana_redeem_progress (
    redemption_id      BLOB    PRIMARY KEY NOT NULL,
    multisig_pda       BLOB    NOT NULL,
    transaction_index  INTEGER NOT NULL,
    execute_signature  TEXT
);

CREATE TABLE solana_signer_cache (
    redemption_id        BLOB    NOT NULL,
    transaction_index    INTEGER NOT NULL,
    step                 TEXT    NOT NULL,
    broadcast_signature  TEXT    NOT NULL,
    broadcast_at_unix    INTEGER NOT NULL,
    PRIMARY KEY (redemption_id, transaction_index, step)
);
