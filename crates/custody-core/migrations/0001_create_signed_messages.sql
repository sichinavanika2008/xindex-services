-- M5 daemon replay/slashing DB (PART 5 / DL-M5-4).
--
-- Three tables — one per signing role — keyed by the identity tuple
-- the on-chain reverts would otherwise rely on. The daemon refuses to
-- sign a SECOND-DIFFERENT message under the same key tuple, never
-- reaches the HSM. Belt-and-suspenders to:
--   * AttestationOracle `SlotAlreadyAttested` (mint side)
--   * IntentQueue delivery-XOR-refund mutex (burn side)
-- and future-proofs non-deterministic schemes (Schnorr / MuSig2).
--
-- `payload_hash` is the SHA-256 of the canonical request bytes (decoded
-- + re-encoded canonical form, not the raw JSON, to defeat re-ordering
-- of fields). It lets the daemon distinguish:
--   * same key tuple + same payload_hash → idempotent (return cached sig)
--   * same key tuple + different payload_hash → 409 Conflict
--
-- `signature` is the bytes returned to the coordinator (so a true replay
-- gets back THE SAME bytes — deterministic ECDSA already gives this for
-- a fixed digest, but storing it makes idempotency observable).

CREATE TABLE IF NOT EXISTS signed_attestations (
    intent_id BLOB NOT NULL,
    -- U256 as a fixed 32-byte big-endian BLOB so the PK ordering is
    -- well-defined and binary-comparable. (TEXT decimal would collate
    -- lexicographically — wrong for numbers.)
    slot_index BLOB NOT NULL,
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (intent_id, slot_index)
);

-- One row per redemption. The single-row-per-id constraint enforces
-- delivery-XOR-refund AT THE DAEMON: an attempt to record `refund` when
-- `delivery` already exists (or vice versa) is a PK violation. The
-- handler distinguishes the violation kinds by reading the existing
-- row's `kind` first.
CREATE TABLE IF NOT EXISTS signed_redemptions (
    redemption_id BLOB NOT NULL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('delivery', 'refund')),
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL
);

-- Keyed by the UTXO the input is spending — signing the same outpoint
-- twice with a different sighash (i.e. a different consuming-tx shape)
-- is the failure mode this guards. Same outpoint + same payload_hash =
-- idempotent re-request; same outpoint + different payload_hash = 409.
CREATE TABLE IF NOT EXISTS signed_psbt_inputs (
    input_txid BLOB NOT NULL,
    input_vout INTEGER NOT NULL,
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (input_txid, input_vout)
);
