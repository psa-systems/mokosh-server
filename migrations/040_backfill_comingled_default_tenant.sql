-- PMS-263 (PMS-255 step 8): backfill + verification for co-mingled
-- default-tenant business rows.
--
-- Resolved decision (product owner, recorded in
-- docs/rls-per-user-isolation.md "Legacy co-mingled data ownership"):
-- Mokosh is not in production. The database is wiped before go-live, so there
-- is NO legacy co-mingled business data to re-home or quarantine. The data
-- backfill is therefore intentionally a no-op: there is nothing to move. This
-- also avoids the unsafe path the analysis flagged earlier, where personal
-- tenants are provisioned lazily on login (PMS-243/245) and a one-shot SQL
-- backfill would have no tenant to resolve most owners to.
--
-- What stays valuable is the invariant this issue exists to prove: under
-- personal-tenant isolation no user-created (business) row may sit in the
-- shared default tenant 00000000-0000-0000-0000-000000000001. That tenant is
-- the co-mingling landing zone every normal user is re-homed OFF of
-- (PMS-243/245), so a business row left there is exactly the cross-user leak
-- this issue targets. Seed lookup/config rows (migration 023) legitimately stay
-- in the default tenant as the per-tenant copy template (TenantService::
-- copy_default_config) and are NOT business, so they are excluded.
--
-- This migration asserts that invariant fail-loud at migrate time. On a fresh /
-- wiped database the business tables hold zero default-tenant rows, so it is a
-- no-op that passes by construction; if any co-mingled business row is ever
-- present it RAISES instead of silently leaving a cross-user leak in place. It
-- performs no writes, so it is idempotent and safe to re-run.
--
-- A standalone, human-runnable form of the same query (for attaching its output
-- to a PR / ad-hoc audit) lives in
-- docs/dev-docs/pms-263-verify-no-comingled-business-rows.sql.

DO $$
DECLARE
    default_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000001';
    -- Business tables (user-created records) per the PMS-255 inventory in
    -- docs/rls-per-user-isolation.md. Lookup/config, auth and per-tenant
    -- sequence tables are intentionally excluded: lookup rows are seeded into
    -- the default tenant on purpose and are not owned by any one user.
    business_tables CONSTANT text[] := ARRAY[
        'companies', 'contacts', 'sites',
        'tickets', 'ticket_notes', 'ticket_attachments',
        'time_entries', 'active_timers', 'time_off', 'user_availability',
        'appointments',
        'projects', 'project_phases', 'tasks', 'task_dependencies',
        'contracts', 'contract_items', 'contract_hour_balances',
        'contract_invoice_runs', 'invoices', 'payments',
        'assets', 'asset_relationships', 'configuration_items',
        'credential_vault', 'asset_audit_log',
        'kb_articles', 'kb_article_votes',
        'notifications', 'rmm_device_mappings', 'files', 'audit_log',
        'email_mailboxes', 'payment_gateway_configs'
    ];
    t text;
    leaked bigint;
    offenders text := '';
    msg text;
BEGIN
    FOREACH t IN ARRAY business_tables LOOP
        EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id = $1', t)
            INTO leaked USING default_tenant;
        IF leaked > 0 THEN
            offenders := offenders || format('  %s: %s row(s)%s', t, leaked, chr(10));
        END IF;
    END LOOP;

    -- Child tables that carry no tenant_id of their own inherit it from their
    -- parent (see "Tables WITHOUT tenant_id" in the reference doc); co-mingling
    -- shows up as a parent row in the default tenant.
    EXECUTE 'SELECT count(*) FROM invoice_lines il JOIN invoices i ON i.id = il.invoice_id WHERE i.tenant_id = $1'
        INTO leaked USING default_tenant;
    IF leaked > 0 THEN
        offenders := offenders || format('  invoice_lines (via invoices): %s row(s)%s', leaked, chr(10));
    END IF;

    EXECUTE 'SELECT count(*) FROM kb_article_versions v JOIN kb_articles a ON a.id = v.article_id WHERE a.tenant_id = $1'
        INTO leaked USING default_tenant;
    IF leaked > 0 THEN
        offenders := offenders || format('  kb_article_versions (via kb_articles): %s row(s)%s', leaked, chr(10));
    END IF;

    IF offenders <> '' THEN
        -- Build the message with format() (%s placeholders) and raise it via a
        -- single %, because RAISE treats %s as "substitute, then literal s".
        msg := format(
            'PMS-263 verification failed: business rows co-mingled in the default tenant %s:%s%s',
            default_tenant, chr(10), offenders
        );
        RAISE EXCEPTION '%', msg USING ERRCODE = 'check_violation';
    END IF;
END $$;
