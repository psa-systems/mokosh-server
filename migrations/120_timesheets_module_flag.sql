-- PMS-943: timesheets become a per-tenant feature, off for a one-person MSP.
--
-- Submitting a week of your own time to yourself for approval is the flow the
-- reporter called out as making no sense, and it was unconditional: the five
-- timesheet routes were mounted for every tenant. Timesheets are an employer's
-- HR function and only mean something once there is more than one person.
--
-- No new mechanism. `module_config` (migration 017) is already the per-tenant
-- feature table, and `RequireModuleEnabled` (PMS-113) is already the extractor
-- that enforces it, returning 404 so a disabled feature is indistinguishable
-- from a route that does not exist. This adds a tenth module name to a table
-- that already holds nine.
--
-- `timesheets` is separate from the existing `time_tracking` module on purpose.
-- Logging time is not the same feature as submitting a week of it: a one-person
-- MSP still logs and still bills, it just has nobody to submit to.
--
-- The initial value is read off `tenants.kind` (migration 019), which already
-- records the distinction the feature needs: `personal` is one self-signed-up
-- person, `org` is the multi-user model. It is a starting value and not the
-- rule, so an organization can turn timesheets off and a one-person tenant that
-- wants them can turn them on.
--
-- ON CONFLICT DO NOTHING rather than an upsert: a tenant that somehow already
-- carries a `timesheets` row has been configured deliberately, and a migration
-- must not overwrite an operator's choice.

INSERT INTO module_config (tenant_id, module_name, is_enabled, config)
SELECT id, 'timesheets', (kind = 'org'), '{}'::jsonb
FROM tenants
ON CONFLICT (tenant_id, module_name) DO NOTHING;
