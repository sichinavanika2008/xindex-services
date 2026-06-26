-- AUD-PSBT-REPLAY-CHAINID: add `chain_id` to the PSBT-input replay key.
--
-- `signed_psbt_inputs` (migration 0001) keyed only on `(input_txid,
-- input_vout)`. A single daemon serving more than one UTXO chain (BTC / LTC
-- / BCH / DOGE / ZEC — DL-P3-1) could then false-conflict on a same-outpoint
-- collision ACROSS chains: outpoints are only unique within a chain, so two
-- distinct UTXOs that happen to share a txid:vout on different chains would
-- collapse to one replay row → a spurious 409 (a stuck redemption), never a
-- mis-sign. Recreate the table with `chain_id` first in the PK.
--
-- Existing rows backfill to 'BTC.BTC' (the only UTXO chain in operation;
-- mirrors the P3.1-6 dispatch.chain backfill). No mainnet data exists yet
-- (BTC custody is DL-P3-7 gated), so this is a clean reshape.

ALTER TABLE signed_psbt_inputs RENAME TO signed_psbt_inputs_old;

CREATE TABLE signed_psbt_inputs (
    chain_id TEXT NOT NULL,
    input_txid BLOB NOT NULL,
    input_vout INTEGER NOT NULL,
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, input_txid, input_vout)
);

INSERT INTO signed_psbt_inputs
    (chain_id, input_txid, input_vout, payload_hash, signature, signed_at_unix)
SELECT 'BTC.BTC', input_txid, input_vout, payload_hash, signature, signed_at_unix
FROM signed_psbt_inputs_old;

DROP TABLE signed_psbt_inputs_old;
