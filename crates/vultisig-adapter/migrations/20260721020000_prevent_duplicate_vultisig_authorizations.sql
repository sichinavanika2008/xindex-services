CREATE UNIQUE INDEX vultisig_keysign_live_authorization_unique
ON vultisig_keysign_journal (authorization_sha256);

CREATE UNIQUE INDEX vultisig_keysign_terminal_authorization_unique
ON vultisig_keysign_terminal_handoffs (authorization_sha256);

-- Refuse to upgrade a journal that already used the old session-only guard to
-- recreate one authorization across the live/terminal boundary. Such a row
-- must be investigated rather than silently becoming recoverable work.
CREATE TABLE vultisig_keysign_authorization_upgrade_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

INSERT INTO vultisig_keysign_authorization_upgrade_guard (valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM vultisig_keysign_journal AS live
    INNER JOIN vultisig_keysign_terminal_handoffs AS terminal
        ON terminal.authorization_sha256 = live.authorization_sha256
);

DROP TABLE vultisig_keysign_authorization_upgrade_guard;

CREATE TRIGGER vultisig_keysign_reject_live_authorization_after_terminal
BEFORE INSERT ON vultisig_keysign_journal
WHEN EXISTS (
    SELECT 1
    FROM vultisig_keysign_terminal_handoffs
    WHERE authorization_sha256 = NEW.authorization_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'vultisig keysign authorization already reached terminal handoff');
END;
