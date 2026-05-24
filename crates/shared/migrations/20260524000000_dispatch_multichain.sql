-- U9 / Phase 3.1: dispatch store learns the per-leg chain.
--
-- Until now the dispatch store implicitly assumed BTC. With the U8
-- multi-role signer and U10 multi-chain executor, the same redemption
-- can dispatch one leg to BTC and another to LTC (etc.), and the
-- signer's THORChain cross-check needs to know which chain to query
-- for the `inbound_txid` recorded against `(rid, leg_index)`.
--
-- Pure additive: existing in-flight rows default to 'btc'. Backwards-
-- compatible with H1's per-leg PK.
--
-- chain values are lowercase (matches `ChainId`'s Display + Serde form).
-- CHECK constraint locks the value to the Phase 3.1 UTXO family; adding
-- a chain in Phase 3.2+ requires a follow-on migration that extends
-- the CHECK list.

ALTER TABLE redemption_dispatch
ADD COLUMN chain TEXT NOT NULL DEFAULT 'btc'
    CHECK(chain IN ('btc', 'ltc', 'bch', 'doge', 'zec'));
