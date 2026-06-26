-- Phase 4.6: TRON account-permission multisig replay/slashing table.
--
-- Mirrors `signed_xrp_txs`, but keyed by `(chain_id, owner_address, txid)`
-- because TRON has NO account nonce — the `txID = sha256(raw_data)` IS the
-- full payload identity:
--   * `chain_id` is the THORChain asset string (`TRON.TRX`) — pinned in
--     `xindex_shared::chain_registry`. Stable across a ChainId re-order.
--   * `owner_address` is the base58check `T…` address of the multisig
--     account (TEXT — TRON addresses are base58 strings, like XRP r-addr).
--   * `txid` is the 32-byte `sha256(raw_data)` (BLOB).
--
-- Distinct redemptions produce distinct `raw_data` (different destination /
-- amount / ref-block) and therefore distinct `txID`s, so they never
-- collide; a re-driven leg within the TAPOS window rebuilds the same
-- `raw_data` → same `txID` → idempotent cached signature.
--
-- `payload_hash` equals `txid` (the value the HSM signs). `signature` is
-- the 65-byte recoverable `r ‖ s ‖ v` (v = recovery id 0/1) appended to
-- `Transaction.signature[]`.

CREATE TABLE IF NOT EXISTS signed_tron_txs (
    chain_id TEXT NOT NULL,
    owner_address TEXT NOT NULL,
    txid BLOB NOT NULL,
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, owner_address, txid)
);
