-- PMS-64: one hour-balance row per (contract item, period).
--
-- consume_hours / roll_to_next_period UPSERT the per-period
-- contract_hour_balances row keyed on
-- (tenant_id, contract_id, contract_item_id, period_start, period_end),
-- so that tuple must be unique. Without this constraint a concurrent
-- consume + rollover could create two rows for the same period and the
-- ON CONFLICT target would have no matching index. Additive: existing
-- data is single-row-per-period already (the service is the only writer).

ALTER TABLE contract_hour_balances
    ADD CONSTRAINT uq_contract_hour_balances_period
        UNIQUE (tenant_id, contract_id, contract_item_id, period_start, period_end);
