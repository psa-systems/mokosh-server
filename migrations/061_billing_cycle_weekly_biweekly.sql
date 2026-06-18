-- PMS-404: add `weekly` and `bi_weekly` to the contracts.billing_cycle
-- closed set. Drop and re-add the CHECK constraint defined in
-- 009_contracts.sql:23 (auto-named `contracts_billing_cycle_check` by
-- Postgres for the inline column CHECK) so weekly and bi-weekly contracts
-- can be created. Canonical tokens are snake_case to match the existing
-- `one_time` convention; the frontend humanizes `bi_weekly` to "Bi-weekly".

ALTER TABLE contracts
    DROP CONSTRAINT contracts_billing_cycle_check;

ALTER TABLE contracts
    ADD CONSTRAINT contracts_billing_cycle_check
    CHECK (billing_cycle IN ('monthly', 'quarterly', 'annually', 'one_time', 'weekly', 'bi_weekly'));
