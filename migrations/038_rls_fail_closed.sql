-- PMS-257: flip the tenant_isolation RLS policy fail-closed, add WITH CHECK,
-- and FORCE row level security so the table owner is no longer exempt.
--
-- Background
-- ----------
-- `024_triggers_and_rls.sql` attached a fail-open, USING-only policy:
--   USING (tenant_id = COALESCE(NULLIF(current_setting('app.current_tenant', true), '')::uuid, tenant_id))
-- An unset `app.current_tenant` GUC collapses to `tenant_id = tenant_id`, so a
-- pooled connection with no tenant context sees EVERY row. Being USING-only it
-- also never constrained INSERT/UPDATE, so a write could set or move a row into
-- another tenant. This migration rewrites the policy on every tenant_id table to
-- be fail-closed and to enforce WITH CHECK on writes.
--
-- Fail-closed form
-- ----------------
--   USING      (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
--   WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
-- With the GUC unset, `current_setting(.., true)` returns NULL, `NULLIF(NULL,'')`
-- is NULL, `NULL::uuid` is NULL, and `tenant_id = NULL` is NULL (never true) -> a
-- read returns zero rows and a write is rejected. An empty-string GUC takes the
-- same NULL path rather than raising an invalid-uuid cast error. The GUC is set
-- transaction-locally by `Database::begin_with_tenant` (src/db/pool.rs).
--
-- DB role posture (which connection uses which role)
-- --------------------------------------------------
-- `FORCE ROW LEVEL SECURITY` makes the policy apply to the table owner too, but
-- it does NOT apply to superusers or roles with the BYPASSRLS attribute - those
-- always bypass RLS. Therefore:
--   * The MIGRATION / owner role MUST bypass RLS (BYPASSRLS, or a superuser) so
--     migrations and seed DML keep operating unrestricted across every tenant.
--   * The APPLICATION role MUST NOT have BYPASSRLS, so the policy actually
--     constrains application queries.
-- Roles are cluster-global and environment-specific, so this migration does not
-- create or alter them (doing so would collide across databases sharing a
-- cluster). Provisioning the unprivileged application role and pointing the app
-- connection at it is a deployment step; until every read path runs through
-- `begin_with_tenant` (parent PMS-255) the application still connects as the
-- bypassing role and relies on explicit `WHERE tenant_id = $1` filters, so this
-- flip is a no-op for the running app and safe to land now. The regression in
-- tests/rls_isolation.rs proves the fail-closed behaviour against an explicitly
-- NOBYPASSRLS role.
--
-- The loop mirrors 024's information_schema selection so it covers exactly the
-- tenant_id tables - including tables created after 024 (027/028/031/032/...)
-- that never received the original policy. DROP POLICY IF EXISTS makes it
-- idempotent and able to replace the 024 policy where it already exists.

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
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format('
            CREATE POLICY tenant_isolation ON %I
            USING (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid
            )
        ', t);
    END LOOP;
END $$;
