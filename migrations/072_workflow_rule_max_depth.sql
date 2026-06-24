-- PMS-467 / PMS-448 phase 3: cycle-cap settings key for mutating
-- workflow rules on transition triggers.
--
-- Phase 3 lets a `ticket.status_changed` or `ticket.priority_changed`
-- rule mutate the same ticket's status or priority. Such a mutation
-- itself fires the matching transition trigger, so the executor
-- enforces a depth cap to prevent runaway recursion. The cap is
-- configured per tenant via this well-known tenant_settings key:
--
--   category = 'workflows'
--   key      = 'rule_max_depth'
--   value    = JSONB integer in 1..=10, default 3 when unset
--
-- 3 covers the "primary change + two follow-up rules" pattern observed
-- in the existing automation engine without making a runaway loop
-- noticeable to the requester. When a rule would fire at depth >= the
-- configured cap, the executor writes a `workflow_rule_runs` row with
-- error = 'cycle cap reached at depth N' instead of applying the
-- actions, so the operator's audit trail captures why the cascade
-- stopped.
--
-- Reader: src/modules/settings/service.rs::read_workflow_rule_max_depth
-- Writer: validated by src/modules/settings/models.rs::validate_setting_value
-- Executor: src/modules/workflows/executor.rs
--
-- This migration seeds the default for every existing tenant so the
-- settings row is browseable from the SPA right after the upgrade. The
-- reader also falls back to 3 when the row is absent (new tenants
-- provisioned after this migration).

INSERT INTO tenant_settings (tenant_id, category, key, value)
SELECT id, 'workflows', 'rule_max_depth', to_jsonb(3)
FROM tenants
ON CONFLICT (tenant_id, category, key) DO NOTHING;
