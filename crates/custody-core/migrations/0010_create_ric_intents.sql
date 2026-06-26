-- CTD-1 / DL-CTD-2: Redemption Intent Certificate (RIC) one-shot table.
--
-- The custody-spend daemon, before signing a PSBT/Safe/Cosmos/XRP/TRON spend,
-- verifies a k-of-n Set-B-signed RIC and binds the spend to its certified
-- destination/amount/memo. This table makes the RIC a ONE-SHOT authorization:
-- a single valid RIC for `(chain_id, redemption_id, leg_index)` cannot be
-- re-driven into N payouts across the family-specific spend-replay keys (the
-- RA-1 killer the v1 RIC missed).
--
-- `payload_hash` is the RIC EIP-712 digest. Same key + same digest + the SAME
-- first-consumed spend identity → idempotent; same digest + a DIFFERENT spend
-- (RUST-003: an account family whose sequence/nonce advanced after the first
-- spend confirmed, or a second BTC tx) → 409; same key + a DIFFERENT digest →
-- 409 Conflict (a forged/rotated cert). The `signature` BLOB is unused for a
-- one-shot (the family replay table holds the real signature), so RUST-003
-- repurposes it to store that first-consumed spend identity.

CREATE TABLE IF NOT EXISTS ric_intents (
    chain_id TEXT NOT NULL,
    redemption_id BLOB NOT NULL,     -- 32 bytes
    leg_index INTEGER NOT NULL,      -- u32 as i64
    payload_hash BLOB NOT NULL,      -- 32-byte RIC digest
    signature BLOB NOT NULL,         -- RUST-003: first-consumed spend identity
                                     -- (cosmos/xrp sequence, tron txID, evm-safe
                                     -- nonce, btc unsigned-tx txid), NOT a signature
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, redemption_id, leg_index)
);
