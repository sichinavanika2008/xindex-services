-- CTD-1 Slice E (DL-CTD-E): per-chain Set-B certification volume windows.
-- One row per (chain, fixed-window bucket); `used` is a decimal TEXT
-- accumulator because EVM-leg amounts exceed SQLite's i64 INTEGER range.
-- Both RIC and ACC signing consume from the same per-chain window — the
-- mint-cancel path must not bypass the breaker.
CREATE TABLE volume_windows (
    chain        TEXT    NOT NULL,
    window_start INTEGER NOT NULL,
    used         TEXT    NOT NULL,
    PRIMARY KEY (chain, window_start)
);
