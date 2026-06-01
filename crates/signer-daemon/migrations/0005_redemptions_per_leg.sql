-- H2 (audit 2026-06-01): key the redemption replay store on
-- (redemption_id, leg_index), not redemption_id alone.
--
-- The store mirrors the on-chain per-leg mutex (IntentQueue
-- `_legForUpdate` keys on (redemptionId, legIndex, assetId)). Keyed on
-- redemption_id ALONE it folds every leg of one redemption into a single
-- row: a leg-1 delivery (same `kind`, different `payload_hash` because
-- `leg_index` differs) matches leg 0's row -> 409 Conflict; a
-- mixed-outcome leg (leg-1 refund after leg-0 delivery) -> MutexViolation.
-- Leg >= 1 could then never reach the on-chain threshold, bricking
-- multi-leg redemptions until the 24h deadline-cancel. Latent today
-- (`leg_index` is hardcoded 0 in xindex-attest-redeem), but it activates
-- with no compile error the moment multi-leg attestation is wired.
--
-- Mirrors the F2 dispatch-store fix (20260520000000_dispatch_per_leg).
-- SQLite cannot ALTER a PRIMARY KEY, so recreate the table preserving
-- existing rows at leg_index 0, then table-swap.

CREATE TABLE signed_redemptions_v2 (
    redemption_id BLOB NOT NULL,
    leg_index INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL CHECK (kind IN ('delivery', 'refund')),
    payload_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_at_unix INTEGER NOT NULL,
    PRIMARY KEY (redemption_id, leg_index)
);

INSERT INTO signed_redemptions_v2
    (redemption_id, leg_index, kind, payload_hash, signature, signed_at_unix)
    SELECT redemption_id, 0, kind, payload_hash, signature, signed_at_unix
    FROM signed_redemptions;

DROP TABLE signed_redemptions;
ALTER TABLE signed_redemptions_v2 RENAME TO signed_redemptions;
