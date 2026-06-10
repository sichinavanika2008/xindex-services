-- CTD-1 / DL-CTD-2: Redemption Intent Certificate (RIC) one-shot table.
--
-- The custody-spend daemon, before signing a PSBT/Safe/Cosmos/XRP/TRON spend,
-- verifies a k-of-n Set-B-signed RIC and binds the spend to its certified
-- destination/amount/memo. This table makes the RIC a ONE-SHOT authorization:
-- a single valid RIC for `(chain_id, redemption_id, leg_index)` cannot be
-- re-driven into N payouts across the family-specific spend-replay keys (the
-- RA-1 killer the v1 RIC missed).
--
-- `payload_hash` is the RIC EIP-712 digest. Same key + same digest → idempotent
-- (return cached signature); same key + a DIFFERENT digest → 409 Conflict (a
-- re-drive with a forged/rotated cert). Mirrors the per-family replay tables.

CREATE TABLE IF NOT EXISTS ric_intents (
    chain_id TEXT NOT NULL,
    redemption_id BLOB NOT NULL,     -- 32 bytes
    leg_index INTEGER NOT NULL,      -- u32 as i64
    payload_hash BLOB NOT NULL,      -- 32-byte RIC digest
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, redemption_id, leg_index)
);
