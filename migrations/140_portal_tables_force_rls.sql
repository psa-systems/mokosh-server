-- PMS-729 phase 2 §5 follow-up: force RLS on portal_refresh_tokens and
-- portal_password_reset_tokens.
--
-- Migrations 102 (H1+H2) and 103 (H3) enabled RLS + a
-- `tenant_isolation` policy but did not FORCE it, so a table owner
-- (BYPASSRLS is off, but the OWNER role still skips policies unless
-- FORCE is set) could read across tenants. Every other portal-touching
-- table (contacts, portal_setup_tokens, portal_mfa's contacts columns,
-- and every deferred table cleaned up by migration 095) sets both
-- ENABLE and FORCE, matching the fail-closed backstop
-- `038_rls_fail_closed.sql` established.
--
-- The `tests/rls_coverage.rs` guard (PMS-683) queries pg_class for
-- both `relrowsecurity` AND `relforcerowsecurity`, so a table missing
-- FORCE fails the check even with the policy in place. This migration
-- restores the invariant for the two portal tables that shipped
-- without it.
--
-- Idempotent: `FORCE ROW LEVEL SECURITY` is a set-to-true operation;
-- re-running is a no-op.

ALTER TABLE portal_refresh_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE portal_password_reset_tokens FORCE ROW LEVEL SECURITY;
