-- C5 (Phase 4.4): XRP `SignerList` multisig replay/slashing table.
--
-- Mirrors `signed_cosmos_txs`. Keyed by `(chain_id, account_address,
-- sequence)`:
--   * `chain_id` is the THORChain asset string (`XRP.XRP`) — pinned in
--     `xindex_shared::chain_registry`. Stable across a ChainId re-order.
--   * `account_address` is the classic r-address of the multisig account
--     (TEXT — XRPL addresses are base58 strings, like Cosmos bech32).
--   * `sequence` is the account's monotonic XRPL `Sequence` (the nonce).
--     Stored as INTEGER (fits i64 for any realistic horizon).
--
-- The PK enforces the daemon-side invariant: at most one signed body per
-- (account, sequence) slot, ever. Because `LastLedgerSequence` is bound
-- into the body, a retry at the same sequence with a different deadline
-- yields a different `payload_hash` and is refused as a Conflict — the
-- executor MUST pick one deadline per sequence (KNOWN_FINDINGS P4.4-2).
--
-- `payload_hash` is THIS daemon's RECOMPUTED per-signer multi-signing
-- digest (32 bytes, `SHA512Half(SMT\0 ‖ body ‖ my_account_id)` — the
-- value the HSM signs). Each member legitimately stores a DIFFERENT
-- payload_hash for the same (chain, account, sequence) because each
-- appends its own AccountID; that is fine — each daemon has its own
-- replay DB. `signature` is the DER-encoded low-S `TxnSignature` (no
-- recovery byte, no sighash byte).

CREATE TABLE IF NOT EXISTS signed_xrp_txs (
    chain_id TEXT NOT NULL,
    account_address TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, account_address, sequence)
);
