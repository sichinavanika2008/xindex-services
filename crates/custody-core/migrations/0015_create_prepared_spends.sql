-- Bind-prepare side-channel (provider correlation id -> unsigned spend + cert).
--
-- The executor stores the unsigned spend + its k-of-n certificate here, keyed
-- by a provider correlation id BEFORE submission. The approval adapter
-- (a separate process) looks it up by request_id to bind the spend before it
-- APPROVE/REJECTs. Shared persistence is REQUIRED because the executor and the
-- approval path may be a distinct process; an in-memory store cannot bridge it.
--
-- Transient: one row per in-flight redeem leg, GC-able once the spend confirms.
CREATE TABLE IF NOT EXISTS prepared_spends (
    request_id      TEXT    PRIMARY KEY,
    spend_json      TEXT    NOT NULL,
    created_at_unix INTEGER NOT NULL
);
