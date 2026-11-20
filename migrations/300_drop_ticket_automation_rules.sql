-- Retire ticket automation: nothing could author rules, so the execution path was dead weight.
DROP INDEX IF EXISTS idx_automation_rules_tenant;
DROP INDEX IF EXISTS idx_automation_rules_trigger;
DROP TABLE IF EXISTS ticket_automation_rules;
