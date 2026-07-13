CREATE TABLE IF NOT EXISTS registry_signature_reservations (
    kind TEXT NOT NULL CHECK (kind IN ('inbound', 'quote')),
    identity BLOB NOT NULL,
    payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
    signature BLOB CHECK (signature IS NULL OR length(signature) = 65),
    reserved_at INTEGER NOT NULL CHECK (reserved_at >= 0),
    signed_at INTEGER CHECK (signed_at IS NULL OR signed_at >= reserved_at),
    PRIMARY KEY (kind, identity)
);

CREATE TABLE IF NOT EXISTS quote_nonce_reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    originator BLOB NOT NULL CHECK (length(originator) = 20),
    nonce INTEGER NOT NULL CHECK (nonce > 0),
    payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'consumed', 'expired')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS quote_nonce_one_active_per_originator
    ON quote_nonce_reservations(originator)
    WHERE state = 'reserved';

CREATE UNIQUE INDEX IF NOT EXISTS quote_nonce_one_consumed_nonce
    ON quote_nonce_reservations(originator, nonce)
    WHERE state = 'consumed';

CREATE INDEX IF NOT EXISTS quote_nonce_history
    ON quote_nonce_reservations(originator, nonce, state);
