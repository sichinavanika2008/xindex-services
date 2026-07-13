CREATE TABLE IF NOT EXISTS thor_source_tip_checkpoints (
    source_id TEXT PRIMARY KEY
        CHECK (length(source_id) BETWEEN 1 AND 128),
    height INTEGER NOT NULL CHECK (height > 0),
    block_hash TEXT NOT NULL CHECK (length(block_hash) > 0),
    observed_at INTEGER NOT NULL CHECK (observed_at > 0),
    advanced_once INTEGER NOT NULL DEFAULT 0 CHECK (advanced_once IN (0, 1))
);
