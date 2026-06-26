-- CTD-1 / DL-CTD-2 Slice C: Acquire-Cancel Certificate (ACC) one-shot table.
--
-- The MINT-CANCEL BTC swap-back is a custody spend rooted on the
-- `AcquireCancelled` event, NOT a redemption. The shared PSBT-input gate
-- accepts a RIC (redeem) XOR an ACC (mint-cancel); for the ACC branch this
-- table makes the certificate a ONE-SHOT authorization so a single valid ACC
-- for `(chain_id, cancel_id)` cannot be re-driven into N swap-backs (the same
-- RA-1 anti-re-drive guard `ric_intents` provides for the redeem path).
--
-- Keyed by `cancel_id` alone (within a chain): `cancelId` is unique per
-- `AcquireCancelled` emission, so it needs no leg/slot sub-key. `payload_hash`
-- is the ACC EIP-712 digest. Same key + same digest -> idempotent (return
-- cached); same key + a DIFFERENT digest -> 409 Conflict (a re-drive with a
-- forged/rotated cert). SEPARATE table from `ric_intents` so the redeem and
-- mint-cancel one-shots can never collide.

-- Same cancel_id + same digest + the SAME first-consumed spend identity (the
-- BTC unsigned-tx txid) -> idempotent; same digest + a DIFFERENT swap-back tx
-- (RUST-003) -> 409. The `signature` BLOB is repurposed to store that identity.
CREATE TABLE IF NOT EXISTS ac_intents (
    chain_id TEXT NOT NULL,
    cancel_id BLOB NOT NULL,         -- 32 bytes
    payload_hash BLOB NOT NULL,      -- 32-byte ACC digest
    signature BLOB NOT NULL,         -- RUST-003: first-consumed spend identity
                                     -- (btc unsigned-tx txid), NOT a signature
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, cancel_id)
);
