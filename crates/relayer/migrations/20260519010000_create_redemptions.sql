-- SD-B stuck-detection tracker for in-flight burn → USDT redemptions.
-- finalize/cancel are event-driven (not from this table); rows past
-- their deadline still present = stuck (operator alert, no auto-action).
CREATE TABLE redemptions (
    redemption_id         BLOB    PRIMARY KEY NOT NULL,
    deadline_unix_secs    INTEGER NOT NULL,
    index_token           BLOB    NOT NULL,
    observed_at_unix_secs INTEGER NOT NULL
);

CREATE INDEX idx_redemptions_deadline ON redemptions(deadline_unix_secs);
