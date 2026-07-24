-- PMS-683: restore the fail-closed RLS backstop on the tenant-scoped tables that
-- were added after the 024/038/039 catch-up loops ran and so never had Row-Level
-- Security enabled. This migration covers the GUC-safe subset; see the scope note.
--
-- Scope decision (IMPORTANT - read before extending this)
-- -------------------------------------------------------
-- The parent issue lists 13 tenant_id tables with no RLS: saved_dashboards,
-- ticket_approvals, tenant_intake_tokens, saved_reports, workflow_rules,
-- workflow_rule_runs, email_intake_log, scheduled_reports, scheduled_dashboards,
-- change_requests, quotes, ticket_templates, quote_sequences.
--
-- The request-serving pool (`mokosh_app`) is NOBYPASSRLS (src/db/pool.rs), so
-- enabling RLS on a table ACTIVELY constrains every app query against it: a query
-- that does not set the `app.current_tenant` GUC (i.e. does not go through
-- `Database::begin_with_tenant`) fail-closes to zero rows. RLS is therefore only
-- safe on a table when EVERY query path to it either sets that GUC via
-- `begin_with_tenant` or runs on the privileged BYPASSRLS `migrator_pool`.
--
-- An audit of the 13 tables' query paths (PMS-683) found only `quotes` and
-- `quote_sequences` are GUC-safe today: all access is in
-- src/modules/quotes/service.rs through `begin_with_tenant` (the portal delegates
-- to the same QuotesService; data_transfer uses `begin_with_tenant`). This
-- migration enables the fail-closed policy on those two tables only.
--
-- The remaining 11 tables are still served by feature services that hold the raw
-- `mokosh_app` pool (`db.pool()`) and query it WITHOUT setting the tenant GUC:
--   * saved_dashboards, scheduled_dashboards -> src/modules/dashboards/service.rs
--   * ticket_approvals, change_requests       -> src/modules/approvals/service.rs
--   * tenant_intake_tokens, email_intake_log  -> src/modules/email_intake/service.rs
--   * saved_reports, scheduled_reports        -> src/modules/saved_reports/service.rs
--   * workflow_rules, workflow_rule_runs      -> src/modules/workflows/service.rs
--   * ticket_templates                        -> src/modules/ticket_templates/service.rs
-- Enabling RLS on any of these before its service moves to `begin_with_tenant`
-- would fail-close its reads and writes in production. That work is the
-- `begin_with_tenant` read-path migration (PMS-256 / PMS-285 lineage): each
-- service should move onto `begin_with_tenant` (and, for `tenant_intake_tokens`,
-- route the cross-tenant secret-hash `resolve_token` lookup through the BYPASSRLS
-- `migrator_pool` or a SECURITY DEFINER resolver) and enable RLS in the SAME
-- change. tests/rls_coverage.rs tracks these 11 as a documented allowlist so no
-- NEW tenant_id table can silently skip RLS the way these did.
--
-- Policy shape mirrors 038_rls_fail_closed.sql / 090 / 091 exactly: an unset or
-- empty `app.current_tenant` collapses to NULL, so USING matches no rows
-- (fail-closed read) and WITH CHECK rejects the write; FORCE binds the owner too.

ALTER TABLE quotes ENABLE ROW LEVEL SECURITY;
ALTER TABLE quotes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON quotes
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE quote_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE quote_sequences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON quote_sequences
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
