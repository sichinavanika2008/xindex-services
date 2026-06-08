-- Burn-side streaming (re-audit-gated): widen the redemption-kind CHECK to
-- admit the combined streamed-settlement kind. A partially-filled streaming
-- redeem swap delivers USDT AND refunds native on ONE leg, attested as a
-- single 'streamed' settlement (the fourth EIP-712 typehash). The replay
-- store keys it like 'delivery'/'refund' on (redemption_id, leg_index), so
-- the per-leg one-shot mutex still holds — a 'delivery'/'refund' after a
-- 'streamed' (and vice versa) is a MutexViolation.
--
-- SQLite cannot ALTER a CHECK constraint, so recreate the table preserving
-- existing rows, then table-swap (mirrors 0005_redemptions_per_leg).

CREATE TABLE signed_redemptions_v3 (
    redemption_id BLOB NOT NULL,
    leg_index INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL CHECK (kind IN ('delivery', 'refund', 'streamed')),
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (redemption_id, leg_index)
);

INSERT INTO signed_redemptions_v3
    (redemption_id, leg_index, kind, payload_hash, signature, signed_at_unix)
    SELECT redemption_id, leg_index, kind, payload_hash, signature, signed_at_unix
    FROM signed_redemptions;

DROP TABLE signed_redemptions;
ALTER TABLE signed_redemptions_v3 RENAME TO signed_redemptions;
