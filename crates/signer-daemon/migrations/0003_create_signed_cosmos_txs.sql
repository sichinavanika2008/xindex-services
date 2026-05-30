-- C5 (Phase 3.3): Cosmos `LegacyAminoPubKey` multisig replay/slashing table.
--
-- Mirrors the per-role pattern of `signed_safe_txs`. Keyed by
-- `(chain_id, account_address, sequence)`:
--   * `chain_id` is the THORChain asset string (`GAIA.ATOM`) — pinned in
--     `xindex_shared::chain_registry`. Stable across a ChainId re-order.
--   * `account_address` is the bech32 multisig account (TEXT, not a fixed
--     20-byte blob like the Safe address — Cosmos addresses are bech32
--     strings of varying HRP length).
--   * `sequence` is the account's monotonic sequence (Cosmos nonce
--     analogue). Stored as INTEGER (fits i64 for any realistic horizon).
--
-- The PK enforces the daemon-side invariant: at most one signed sign-doc
-- per (account, sequence) slot, ever. A second-different request at the
-- same sequence is a coordinator bug or attack — `check_cosmos_tx` caught
-- it before the HSM, and the UNIQUE constraint is the second line of
-- defence against a check/record race.
--
-- `payload_hash` is the daemon's RECOMPUTED amino StdSignDoc sign-bytes
-- hash (32 bytes, SHA-256 of the canonical JSON — the value the HSM
-- signs), so idempotent replay returns the cached signature byte-exact.
-- `signature` is the 64-byte compact low-S r||s (no recovery byte).

CREATE TABLE IF NOT EXISTS signed_cosmos_txs (
    chain_id TEXT NOT NULL,
    account_address TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, account_address, sequence)
);
