-- Durable write-ahead state for the BitGo final-sign-and-broadcast boundary.
CREATE TABLE IF NOT EXISTS bitgo_workflows (
    sequence_id          TEXT PRIMARY KEY,
    policy_commitment    BLOB NOT NULL CHECK (length(policy_commitment) = 32),
    phase                TEXT NOT NULL CHECK (phase IN (
        'build_reserved',
        'built',
        'intent_authorized',
        'user_signed',
        'send_reserved',
        'pending_approval',
        'rejected',
        'broadcast'
    )),
    build_request        BLOB NOT NULL,
    build_response       BLOB,
    unsigned_psbt        BLOB,
    authorization_receipt BLOB,
    authorization_valid_until_unix INTEGER,
    half_signed_tx       BLOB,
    send_request         BLOB,
    send_response        BLOB,
    pending_approval_id  TEXT,
    transfer_id          TEXT,
    txid                 BLOB CHECK (txid IS NULL OR length(txid) = 32),
    final_tx             BLOB,
    created_at_unix      INTEGER NOT NULL,
    updated_at_unix      INTEGER NOT NULL,
    CHECK (
        phase = 'build_reserved'
        OR (build_response IS NOT NULL AND unsigned_psbt IS NOT NULL)
    ),
    CHECK (
        (phase IN ('build_reserved', 'built')
            AND authorization_receipt IS NULL
            AND authorization_valid_until_unix IS NULL)
        OR (phase NOT IN ('build_reserved', 'built')
            AND authorization_receipt IS NOT NULL
            AND authorization_valid_until_unix IS NOT NULL)
    ),
    CHECK (
        phase IN ('build_reserved', 'built', 'intent_authorized')
        OR (half_signed_tx IS NOT NULL AND send_request IS NOT NULL)
    ),
    CHECK (
        phase != 'pending_approval' OR pending_approval_id IS NOT NULL
    ),
    CHECK (
        phase != 'broadcast'
        OR (send_response IS NOT NULL AND transfer_id IS NOT NULL
            AND txid IS NOT NULL AND final_tx IS NOT NULL)
    )
);

-- Append-only, content-addressed raw artifacts. The current row carries the
-- active state; this table preserves every retained provider response.
CREATE TABLE IF NOT EXISTS bitgo_workflow_artifacts (
    sequence_id      TEXT NOT NULL REFERENCES bitgo_workflows(sequence_id),
    ordinal          INTEGER NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN (
        'build_request',
        'wallet_response',
        'wallet_snapshot',
        'build_response',
        'unsigned_psbt',
        'intent_authorization',
        'user_signed_tx',
        'send_request',
        'send_response',
        'pending_approval',
        'pending_approval_lookup',
        'approval_transfer_lookup',
        'final_tx',
        'transfer_lookup'
    )),
    payload_sha256   BLOB NOT NULL CHECK (length(payload_sha256) = 32),
    payload          BLOB NOT NULL,
    created_at_unix  INTEGER NOT NULL,
    PRIMARY KEY (sequence_id, ordinal),
    UNIQUE (sequence_id, kind, payload_sha256)
);
