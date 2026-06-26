-- V5 (Phase 3.2): Safe v1.4.1 `execTransaction` replay/slashing table.
--
-- Mirrors the per-role pattern of the other `signed_*` tables. Keyed by
-- `(chain_id, safe_address, nonce)`:
--   * `chain_id` is the THORChain asset string (`ETH.ETH` / `BSC.BNB` /
--     etc.) — pinned in `xindex_shared::chain_registry`. Stable string
--     identifier; survives a future ChainId enum re-ordering.
--   * `safe_address` is the 20-byte Safe proxy contract address.
--   * `nonce` is the Safe's monotonic uint256 nonce. Stored as `INTEGER`
--     because Safe nonces fit in i64 for any realistic horizon (one
--     execTransaction per second forever = 584B years).
--
-- The PK enforces the daemon-side invariant: at most one signed digest
-- per Safe-nonce slot, ever. A SECOND-DIFFERENT request at the same
-- nonce is a coordinator bug or attack — the handler caught it via
-- `check_safe_tx` BEFORE reaching the HSM, but the UNIQUE constraint
-- is the second line of defence (against a check / record race).
--
-- `payload_hash` is the daemon's RECOMPUTED `safeTxHash` (32 bytes —
-- `keccak256(0x1901 || domainSeparator || structHash)`). Same as the
-- HSM-signed digest, so idempotent replay can return the cached
-- signature byte-exact without touching the HSM.

CREATE TABLE IF NOT EXISTS signed_safe_txs (
    chain_id TEXT NOT NULL,
    safe_address BLOB NOT NULL,
    nonce INTEGER NOT NULL,
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, safe_address, nonce)
);
