-- CTD-1 / DL-CTD-2 Slice C: Set-B signed Acquire-Cancel Certificates
-- (non-equivocation arm).
--
-- A Set-B daemon, before signing an ACC via /api/v1/sign/eip712-acc,
-- consults this table: same (chain_id, cancel_id) + same digest ->
-- idempotent (return the cached ACC signature); same key + a DIFFERENT
-- digest -> 409 Conflict (this signer refuses to certify two different
-- mint-cancel swap-backs for one cancelId, so a compromised relay cannot
-- collect k-of-n over conflicting certificates from honest daemons).
--
-- SEPARATE from ac_intents (migration 0012), mirroring the ric_certs /
-- ric_intents split: a multi-role daemon must never conflate "I certified
-- this cancel" (this table — stores the ACC signature) with "I authorized
-- the swap-back spend" (ac_intents — the one-shot spend authorization).

CREATE TABLE IF NOT EXISTS ac_certs (
    chain_id TEXT NOT NULL,
    cancel_id BLOB NOT NULL,         -- 32 bytes
    payload_hash BLOB NOT NULL,      -- 32-byte ACC digest
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (chain_id, cancel_id)
);
