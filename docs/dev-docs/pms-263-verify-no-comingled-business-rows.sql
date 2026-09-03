-- PMS-263 verification query: zero co-mingled business rows in the default tenant.
--
-- Standalone, human-runnable form of the assertion embedded in
-- migrations/040_backfill_comingled_default_tenant.sql. Run it against a
-- migrated database and attach the output to the PR. Every business table must
-- report comingled_rows = 0; a non-zero count is a cross-user leak (a
-- user-created row left in the shared default tenant
-- 00000000-0000-0000-0000-000000000001, which every normal user is re-homed off
-- of by PMS-243/245).
--
-- Lookup/config, auth and per-tenant sequence tables are intentionally NOT
-- listed: their rows are seeded into the default tenant on purpose (migration
-- 023) as the per-tenant copy template and are not owned by any one user.
--
-- Business-table set and child-table parent joins follow the PMS-255 inventory
-- in docs/rls-per-user-isolation.md. Run with, e.g.:
--   psql "$DATABASE_URL" -f docs/dev-docs/pms-263-verify-no-comingled-business-rows.sql

\set default_tenant '00000000-0000-0000-0000-000000000001'

SELECT table_name, comingled_rows
FROM (
    SELECT 'companies'              AS table_name, count(*) AS comingled_rows FROM companies              WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'contacts',                   count(*) FROM contacts                  WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'sites',                      count(*) FROM sites                     WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'tickets',                    count(*) FROM tickets                   WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'ticket_notes',               count(*) FROM ticket_notes              WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'ticket_attachments',         count(*) FROM ticket_attachments        WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'time_entries',               count(*) FROM time_entries              WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'active_timers',              count(*) FROM active_timers             WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'time_off',                   count(*) FROM time_off                  WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'user_availability',          count(*) FROM user_availability         WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'appointments',               count(*) FROM appointments              WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'projects',                   count(*) FROM projects                  WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'project_phases',             count(*) FROM project_phases            WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'tasks',                      count(*) FROM tasks                     WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'task_dependencies',          count(*) FROM task_dependencies         WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'contracts',                  count(*) FROM contracts                 WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'contract_items',             count(*) FROM contract_items            WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'contract_hour_balances',     count(*) FROM contract_hour_balances    WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'contract_invoice_runs',      count(*) FROM contract_invoice_runs     WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'invoices',                   count(*) FROM invoices                  WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'payments',                   count(*) FROM payments                  WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'assets',                     count(*) FROM assets                    WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'asset_relationships',        count(*) FROM asset_relationships       WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'configuration_items',        count(*) FROM configuration_items       WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'credential_vault',           count(*) FROM credential_vault          WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'asset_audit_log',            count(*) FROM asset_audit_log           WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'kb_articles',                count(*) FROM kb_articles               WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'kb_article_votes',           count(*) FROM kb_article_votes          WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'notifications',              count(*) FROM notifications             WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'rmm_device_mappings',        count(*) FROM rmm_device_mappings       WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'files',                      count(*) FROM files                     WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'audit_log',                  count(*) FROM audit_log                 WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'email_mailboxes',            count(*) FROM email_mailboxes           WHERE tenant_id = :'default_tenant'
    UNION ALL SELECT 'payment_gateway_configs',    count(*) FROM payment_gateway_configs   WHERE tenant_id = :'default_tenant'
    -- child tables without their own tenant_id: judged by the parent's tenant
    UNION ALL SELECT 'invoice_lines (via invoices)',
        count(*) FROM invoice_lines il JOIN invoices i ON i.id = il.invoice_id WHERE i.tenant_id = :'default_tenant'
    UNION ALL SELECT 'kb_article_versions (via kb_articles)',
        count(*) FROM kb_article_versions v JOIN kb_articles a ON a.id = v.article_id WHERE a.tenant_id = :'default_tenant'
) leaks
ORDER BY comingled_rows DESC, table_name;
