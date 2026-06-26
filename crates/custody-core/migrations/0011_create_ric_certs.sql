-- CTD-1 / DL-CTD-2 Slice A.7: Set-B signed Redemption Intent
-- Certificates (non-equivocation arm).
--
-- A Set-B daemon, before signing a RIC via /api/v1/sign/eip712-ric,
-- consults this table: same (chain_id, redemption_id, leg_index) + same
-- digest -> idempotent (return the cached RIC signature); same key + a
-- DIFFERENT digest -> 409 Conflict (this signer refuses to certify two
-- different intents for one leg, so a compromised relay cannot collect
-- k-of-n over conflicting certificates from honest daemons).
--
-- SEPARATE from ric_intents (migration 0010) on purpose: a multi-role
-- daemon must never conflate "I certified this intent" (this table —
-- stores the RIC signature) with "I authorized the custody spend"
-- (ric_intents — the one-shot spend authorization). Sharing one table
-- would let a custody-side idempotency probe return a RIC signature as
-- if it were a cached spend authorization.

CREATE TABLE IF NOT EXISTS ric_certs (
    chain_id TEXT NOT NULL,
    redemption_id BLOB NOT NULL,     -- 32 bytes
    leg_index INTEGER NOT NULL,      -- u32 as i64
    payload_hash BLOB NOT NULL,      -- 32-byte RIC digest
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, redemption_id, leg_index)
);
