-- P-SOL-6 (Phase 4.5): Solana Squads replay table.
--
-- The solana-tx daemon handler previously recorded no replay row — it relied
-- solely on the on-chain Squads program rejecting a duplicate create (PDA
-- collision) / approve (member already voted) / execute (proposal Executed).
-- This adds the daemon-side defense-in-depth keyed on the on-chain step
-- identity `(chain_id, multisig, transaction_index, kind, member)`.
--
-- `payload_hash` is the SEMANTIC intent (kind + transaction_index +
-- destination + amount + memo) and deliberately EXCLUDES the volatile
-- `recent_blockhash`: a re-sign with a fresh blockhash for the same intent is
-- idempotent (the handler re-signs the fresh message — ed25519 is
-- deterministic and local), while a DIFFERENT destination/amount at an
-- already-used step is a 409 Conflict. `signature` stores the first ed25519
-- signature; the conflict check, not the cached bytes, is the guarantee.

CREATE TABLE IF NOT EXISTS signed_solana_txs (
    chain_id TEXT NOT NULL,
    multisig TEXT NOT NULL,
    transaction_index INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('create', 'approve', 'execute')),
    member TEXT NOT NULL,
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, multisig, transaction_index, kind, member)
);
