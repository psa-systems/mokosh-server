-- PMS-1040: bring `contact_notification_preferences` and
-- `tenant_memberships` under the fail-closed `tenant_isolation` backstop
-- that `tests/rls_coverage.rs` (PMS-683 / PMS-874) enforces.
--
-- Both tables arrived from the contact-login line of work after the
-- coverage guard's allowlist had been emptied, and the guard did not run
-- on `main` (integration.yml fires only on pull_request, DEV-612, and
-- `cargo test --tests` stops at the first failing binary), so they landed
-- uncovered. Three sibling tables from the same line stay uncovered on
-- purpose and are named on the exemption lists in that test file instead:
-- `tenant_membership_entitlements`, `identities` and `platform_admins`.
--
-- Policy shape mirrors 038_rls_fail_closed.sql / 094 / 095 exactly: an
-- unset OR empty-string `app.current_tenant` collapses to NULL through
-- NULLIF, so USING matches no rows and WITH CHECK rejects the write;
-- FORCE binds the table owner too. The GUC is set transaction-locally by
-- `Database::begin_with_tenant` (src/db/pool.rs).
--
-- contact_notification_preferences
-- --------------------------------
-- Migration 149 already ENABLEd RLS and attached a policy, but named it
-- `tenant_isolation_contact_notification_prefs` and never FORCEd it, so
-- the coverage guard (which looks for `relforcerowsecurity` AND a policy
-- named exactly `tenant_isolation`) counted the table as uncovered. The
-- 149 policy is DROPped rather than left beside the new one: permissive
-- policies are OR'd, so keeping it would add nothing, and its predicate
-- casts `current_setting('app.current_tenant', true)::UUID` with no
-- NULLIF. A custom GUC that has been SET LOCAL once reverts to the empty
-- string (not NULL) at end of transaction, so on a pooled connection that
-- predicate raises `invalid input syntax for type uuid: ""` where the
-- NULLIF form fail-closes. Same table, no behaviour given up.
--
-- The one SQL reader is `NotificationService::load_contact_preferences`
-- (src/modules/notifications/service.rs), which runs on
-- `begin_with_tenant`, so it is GUC-safe.
--
-- tenant_memberships: reader audit (PMS-1040 acceptance criterion)
-- ---------------------------------------------------------------
-- Migration 157's header claims both identity-plane tables are read "on
-- the migrator pool with no tenant GUC". That claim is what this issue
-- exists to distrust, so it was checked against the code rather than the
-- comment: `grep -rn "tenant_memberships" --include=*.rs` for every file
-- naming the table, then `grep -rn "MembershipRepo::"` for every call
-- site, then the pool expression read at each one.
--
--   * src/db/identity.rs - the only file with SQL against the table
--     (`MembershipRepo::list_active_for_identity`, `find`,
--     `find_id_by_email_and_tenant`, `list_views_for_identity`). Each
--     takes the `&PgPool` its caller supplies, so the pool is decided at
--     the call site, not here.
--   * src/modules/auth/middleware.rs:201 - `db().migrator_pool()`.
--   * src/modules/auth/service.rs:3396, :3541, :3863 - `migrator_pool()`
--     (the :3541 and :3636 sites share the `pool` bound at :3517).
--   * src/modules/tenants/routes.rs:249, :332 - `migrator_pool()`.
--
-- Every one is the BYPASSRLS migrator pool; no reader takes the bare
-- NOBYPASSRLS `.pool()`. The table therefore gets the policy as a
-- backstop rather than going to `ALLOWED_WITHOUT_RLS`.
--
-- Migrations are immutable, so 157's header sentence "neither table is
-- RLS-enabled" cannot be corrected in place. It is superseded here for
-- `tenant_memberships`; `identities` keeps the exemption and is now named
-- in `TENANTLESS_WITHOUT_RLS` (tests/rls_coverage.rs), where it is
-- enforced rather than asserted.
--
-- Writes reach the table only through `sync_user_to_identity_and_membership`
-- (installed by 157, last replaced by 164), the AFTER INSERT OR UPDATE
-- trigger on `users`. `users` has carried ENABLEd + FORCEd RLS since 038,
-- so any `users` write that succeeds today either runs as BYPASSRLS (the
-- trigger then bypasses too, triggers running as the invoking role) or ran
-- with `app.current_tenant` equal to that row's `tenant_id`. The trigger
-- propagates `NEW.tenant_id` into both the INSERT and the UPDATE, so the
-- value it writes is the value the GUC already had to match. Adding the
-- policy cannot fail-close a mirror write that works now.

ALTER TABLE contact_notification_preferences FORCE ROW LEVEL SECURITY;
DROP POLICY tenant_isolation_contact_notification_prefs
    ON contact_notification_preferences;
CREATE POLICY tenant_isolation ON contact_notification_preferences
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_memberships
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
