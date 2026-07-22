CREATE TABLE vultisig_keysign_journal_config (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    target_id BLOB NOT NULL CHECK (length(target_id) = 32)
) STRICT;

CREATE TABLE vultisig_keysign_journal (
    session_id TEXT PRIMARY KEY,
    target_id BLOB NOT NULL CHECK (length(target_id) = 32),
    authorization BLOB NOT NULL CHECK (length(authorization) > 0),
    authorization_sha256 BLOB NOT NULL CHECK (length(authorization_sha256) = 32),
    connector_state BLOB NOT NULL CHECK (length(connector_state) > 0),
    connector_state_sha256 BLOB NOT NULL CHECK (length(connector_state_sha256) = 32),
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT, WITHOUT ROWID;
