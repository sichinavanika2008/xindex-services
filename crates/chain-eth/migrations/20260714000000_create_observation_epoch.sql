CREATE TABLE IF NOT EXISTS evm_observer_epochs (
    observer_id TEXT PRIMARY KEY NOT NULL,
    observation_epoch INTEGER NOT NULL CHECK(observation_epoch >= 0)
);
