-- Bind both sides of settlement credit one-to-one. The original primary keys
-- prevented one physical arrival from being credited to two logical legs;
-- these unique indexes also prevent one logical leg from switching to a
-- second physical arrival/amount after a restart or upstream-view change.
CREATE UNIQUE INDEX IF NOT EXISTS idx_consumed_inflow_logical_unique
    ON consumed_inflow(redemption_id, leg_index);

CREATE UNIQUE INDEX IF NOT EXISTS idx_consumed_native_lifecycle_unique
    ON consumed_native_inflow(flow_kind, lifecycle_id, leg_index);
