CREATE TABLE vultisig_keysign_terminal_handoffs (
    session_id TEXT PRIMARY KEY,
    target_id BLOB NOT NULL CHECK (length(target_id) = 32),
    authorization_sha256 BLOB NOT NULL CHECK (length(authorization_sha256) = 32),
    connector_state_sha256 BLOB NOT NULL CHECK (length(connector_state_sha256) = 32),
    completion_id BLOB NOT NULL CHECK (length(completion_id) = 32),
    downstream_consumer_id BLOB NOT NULL CHECK (length(downstream_consumer_id) = 32),
    downstream_receipt_id BLOB NOT NULL CHECK (length(downstream_receipt_id) = 32),
    acknowledged_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT, WITHOUT ROWID;

CREATE TRIGGER vultisig_keysign_reject_live_after_terminal
BEFORE INSERT ON vultisig_keysign_journal
WHEN EXISTS (
    SELECT 1
    FROM vultisig_keysign_terminal_handoffs
    WHERE session_id = NEW.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'vultisig keysign session already reached terminal handoff');
END;
