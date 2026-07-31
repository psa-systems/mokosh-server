-- PMS-683 (tail): complete the fail-closed RLS backstop begun in
-- 094_rls_quotes_backstop.sql. That migration covered only the two GUC-safe
-- tables (quotes, quote_sequences) and left the remaining 11 tenant-scoped
-- tables in the tests/rls_coverage.rs allowlist because their feature services
-- still queried the raw NOBYPASSRLS `mokosh_app` pool without setting the
-- `app.current_tenant` GUC. Those services have now been migrated onto
-- `Database::begin_with_tenant` (which sets the GUC transaction-locally), so
-- enabling RLS on their tables no longer fail-closes them.
--
-- Table -> service (all now route every tenant-scoped statement through
-- begin_with_tenant; cross-tenant sweeps in the scheduled workers already run
-- on the BYPASSRLS migrator pool):
--   * saved_dashboards, scheduled_dashboards -> src/modules/dashboards/service.rs
--   * ticket_approvals, change_requests       -> src/modules/approvals/service.rs
--       (the route-layer parent-existence check now runs via begin_with_tenant)
--   * tenant_intake_tokens, email_intake_log  -> src/modules/email_intake/service.rs
--   * saved_reports, scheduled_reports        -> src/modules/saved_reports/service.rs
--   * workflow_rules, workflow_rule_runs      -> src/modules/workflows/service.rs
--       (workflow_rule_runs is also written by WorkflowExecutor, which runs
--        inside the ticket service's own begin_with_tenant transaction)
--   * ticket_templates                        -> src/modules/ticket_templates/service.rs
--
-- SPECIAL CASE - tenant_intake_tokens: the email-intake `resolve_token`
-- lookup matches a presented bearer's SHA-256 against every tenant's tokens and
-- is cross-tenant BY DESIGN (the bearer is the only identity, so there is no
-- tenant context to set as the GUC). That single lookup, plus its paired
-- `last_used_at` bump, runs on the BYPASSRLS `migrator_pool` with an explicit
-- SAFETY note at the call site; every OTHER access to the table is tenant-scoped
-- via begin_with_tenant. RLS is therefore safe to enable here too.
--
-- Policy shape mirrors 038_rls_fail_closed.sql / 090 / 091 / 094 exactly: an
-- unset or empty `app.current_tenant` collapses to NULL, so USING matches no
-- rows (fail-closed read) and WITH CHECK rejects the write; FORCE binds the
-- table owner too so even the schema owner cannot bypass the policy.

ALTER TABLE saved_dashboards ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_dashboards FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON saved_dashboards
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE scheduled_dashboards ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_dashboards FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scheduled_dashboards
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE ticket_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ticket_approvals
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE change_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE change_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON change_requests
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE tenant_intake_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_intake_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_intake_tokens
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE email_intake_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_intake_log FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON email_intake_log
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE saved_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON saved_reports
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE scheduled_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scheduled_reports
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE workflow_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workflow_rules
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE workflow_rule_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_rule_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workflow_rule_runs
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE ticket_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ticket_templates
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
