-- MAPPS-330: every Mokosh user is an admin of their own instance.
--
-- Existing rows seeded under the old taxonomy (technician / manager /
-- dispatcher / sales / finance) predate this doctrine and would otherwise sit
-- below the new admin floor until their next Bunyip RS login triggered
-- reconciliation. Backfill them in place so the role surface in the DB
-- matches the runtime authorization on the very first request after deploy.
--
-- super_admin is left alone: it is Bunyip's platform-level role and is
-- granted exclusively by reconciliation against the `bunyip_role = 'admin'`
-- claim, never by an invite or self-signup. The `users` table carries no
-- soft-delete column (`status` flips active / inactive / pending in place),
-- and the runtime reconciliation runs against every row regardless of
-- status, so the backfill scopes to role only and matches that surface.
UPDATE users
SET role = 'admin', updated_at = NOW()
WHERE role NOT IN ('super_admin', 'admin');
