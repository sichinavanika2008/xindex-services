-- Atomic connector -> broadcast handoff commitment.
--
-- These columns are nullable only for retained standalone broadcast-library
-- tests and any pre-integration prepared rows. The integrated Bitcoin runtime
-- inserts every connector identity in the same statement as the evidence and
-- transaction bytes, so a crash cannot leave a connector completion without a
-- durable downstream receipt or vice versa.

ALTER TABLE vultisig_bitcoin_broadcasts
    ADD COLUMN connector_target_id BLOB;
ALTER TABLE vultisig_bitcoin_broadcasts
    ADD COLUMN connector_completion_id BLOB;
ALTER TABLE vultisig_bitcoin_broadcasts
    ADD COLUMN connector_session_id TEXT;
ALTER TABLE vultisig_bitcoin_broadcasts
    ADD COLUMN connector_wire_sha256 BLOB;
ALTER TABLE vultisig_bitcoin_broadcasts
    ADD COLUMN connector_operation_id BLOB;
ALTER TABLE vultisig_bitcoin_broadcasts
    ADD COLUMN connector_transaction_sha256 BLOB;
ALTER TABLE vultisig_bitcoin_broadcasts
    ADD COLUMN connector_handoff_receipt_id BLOB;

CREATE UNIQUE INDEX idx_vultisig_bitcoin_connector_completion
    ON vultisig_bitcoin_broadcasts(connector_completion_id)
    WHERE connector_completion_id IS NOT NULL;

CREATE UNIQUE INDEX idx_vultisig_bitcoin_connector_session
    ON vultisig_bitcoin_broadcasts(connector_session_id)
    WHERE connector_session_id IS NOT NULL;

CREATE UNIQUE INDEX idx_vultisig_bitcoin_connector_operation
    ON vultisig_bitcoin_broadcasts(connector_operation_id)
    WHERE connector_operation_id IS NOT NULL;

CREATE UNIQUE INDEX idx_vultisig_bitcoin_connector_receipt
    ON vultisig_bitcoin_broadcasts(connector_handoff_receipt_id)
    WHERE connector_handoff_receipt_id IS NOT NULL;
