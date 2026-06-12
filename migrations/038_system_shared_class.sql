-- PMS-259: reserve the system-shared, read-only lookup class.
--
-- Editable lookup tables are isolated per personal tenant and seeded at
-- provisioning (see `TenantService::copy_default_config` and
-- `dev-docs/rls-per-user-isolation.md`). A second, distinct class is reserved
-- here for genuinely non-editable, globally shared rows (e.g. future system
-- statuses, maintenance windows): a row with `tenant_id IS NULL` is "global /
-- system-shared". It is readable by every tenant and writable only by a
-- privileged session.
--
-- This migration is STRUCTURAL ONLY: no table opts in and no system-shared row
-- exists yet. Every lookup `tenant_id` column is still `NOT NULL`, so the read
-- clause and write guard below are no-ops for current data; they reserve the
-- mechanism so a table can opt in later via `mokosh_enable_system_shared(...)`.

-- ============================================================================
-- READ SIDE: globally-shared rows are visible to every tenant
-- ============================================================================
--
-- Recreate the migration-024 `tenant_isolation` policy on every `tenant_id`
-- table, adding `tenant_id IS NULL` so system-shared rows are readable
-- regardless of the `app.current_tenant` GUC. The fail-open tenant match is
-- unchanged here; flipping it fail-closed and adding WITH CHECK is PMS-257.
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT table_name
        FROM information_schema.columns
        WHERE column_name = 'tenant_id'
        AND table_schema = 'public'
        AND table_name != 'tenants'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format($pol$
            CREATE POLICY tenant_isolation ON %I
            USING (
                tenant_id IS NULL
                OR tenant_id = COALESCE(
                    NULLIF(current_setting('app.current_tenant', true), '')::UUID,
                    tenant_id
                )
            )
        $pol$, t);
    END LOOP;
END $$;

-- ============================================================================
-- WRITE SIDE (DB guard): system-shared rows are read-only
-- ============================================================================
--
-- Forbid INSERT / UPDATE / DELETE of a system-shared row (`tenant_id IS NULL`)
-- unless the session explicitly sets `app.allow_system_writes = 'on'` (reserved
-- for the migration / super-admin role). The application layer enforces the
-- same rule before it would ever write a system row (documented in
-- `dev-docs/rls-per-user-isolation.md`); this trigger is the DB backstop.
CREATE OR REPLACE FUNCTION mokosh_guard_system_shared_row()
RETURNS TRIGGER AS $$
DECLARE
    affected_tenant UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        affected_tenant := OLD.tenant_id;
    ELSE
        affected_tenant := NEW.tenant_id;
    END IF;

    IF affected_tenant IS NULL
       AND COALESCE(NULLIF(current_setting('app.allow_system_writes', true), ''), 'off') <> 'on'
    THEN
        RAISE EXCEPTION
            'system-shared rows (tenant_id IS NULL) are read-only; set app.allow_system_writes to ''on'' to write'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- OPT-IN HELPER (not invoked on any table yet)
-- ============================================================================
--
-- Register the system-shared class on a lookup table: make its `tenant_id`
-- nullable (so a NULL = global row is storable) and attach the write guard.
-- To add a system-shared lookup later:
--     SELECT mokosh_enable_system_shared('ticket_statuses');
-- then INSERT the global rows from a session with app.allow_system_writes='on'.
CREATE OR REPLACE FUNCTION mokosh_enable_system_shared(target regclass)
RETURNS void AS $$
BEGIN
    EXECUTE format('ALTER TABLE %s ALTER COLUMN tenant_id DROP NOT NULL', target);
    EXECUTE format('DROP TRIGGER IF EXISTS guard_system_shared_row ON %s', target);
    EXECUTE format($trg$
        CREATE TRIGGER guard_system_shared_row
        BEFORE INSERT OR UPDATE OR DELETE ON %s
        FOR EACH ROW EXECUTE FUNCTION mokosh_guard_system_shared_row()
    $trg$, target);
END;
$$ LANGUAGE plpgsql;
