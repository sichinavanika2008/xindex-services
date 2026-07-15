CREATE TABLE IF NOT EXISTS registry_signature_generations (
    kind TEXT NOT NULL CHECK (kind IN ('inbound', 'quote')),
    identity BLOB NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
    signature BLOB CHECK (signature IS NULL OR length(signature) = 65),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'signed', 'expired', 'superseded')),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    reserved_at INTEGER NOT NULL CHECK (reserved_at >= 0),
    signed_at INTEGER CHECK (signed_at IS NULL OR signed_at >= reserved_at),
    updated_at INTEGER NOT NULL CHECK (updated_at >= reserved_at),
    PRIMARY KEY (kind, identity, generation)
);

-- Preserve pre-generation reservations conservatively. The legacy report
-- families were bounded to ten minutes, so reserved_at + 600 is the latest
-- safe retirement point available from the old schema.
INSERT OR IGNORE INTO registry_signature_generations
    (kind, identity, generation, payload_hash, signature, state, expires_at,
     reserved_at, signed_at, updated_at)
SELECT kind,
       identity,
       reserved_at + 600,
       payload_hash,
       signature,
       CASE WHEN signature IS NULL THEN 'reserved' ELSE 'signed' END,
       reserved_at + 600,
       reserved_at,
       signed_at,
       COALESCE(signed_at, reserved_at)
FROM registry_signature_reservations;

CREATE UNIQUE INDEX IF NOT EXISTS registry_signature_one_active_generation
    ON registry_signature_generations(kind, identity)
    WHERE state IN ('reserved', 'signed');

CREATE INDEX IF NOT EXISTS registry_signature_generation_history
    ON registry_signature_generations(kind, identity, generation, state);
