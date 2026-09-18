-- MAPPS-877: promote `read_only` to a first-class `users.role` value.
--
-- BUNYIP-674's PMS-1162 grant-role vocabulary already includes
-- `read_only` (`admin | manager | technician | finance | read_only`),
-- but mokosh's own `users.role` CHECK constraint never listed it, so
-- `map_grant_role` (`src/modules/auth/mokosh_bunyip_grants.rs`)
-- projected `read_only` grantees onto `technician`. That grant of
-- technician-level WRITE access on a workspace the grantee is meant
-- to view read-only is the module-doc "deliberately over-privileged
-- for now" bullet at line 40 there, deferred until the grant surface
-- had testing traffic. It does now.
--
-- Widens the CHECK constraint on `users.role` and on
-- `tenant_invitations.role` (migration 035) to accept `read_only`.
-- No data migration is needed: no row can carry `read_only` today
-- because the constraint refused it, so widening the accepted set is
-- purely additive. The `UserRole::ReadOnly` variant lands in the
-- same commit; every write path that used to admit any authenticated
-- user must now gate on `caller.role.can_write()` and refuse a
-- `ReadOnly` caller (see `RequireWriteAccess` in
-- `src/modules/auth/middleware.rs`).

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_role_check;

ALTER TABLE users
    ADD CONSTRAINT users_role_check
    CHECK (role IN (
        'super_admin', 'admin', 'manager', 'technician',
        'dispatcher', 'sales', 'finance', 'read_only'
    ));

ALTER TABLE tenant_invitations
    DROP CONSTRAINT IF EXISTS tenant_invitations_role_check;

ALTER TABLE tenant_invitations
    ADD CONSTRAINT tenant_invitations_role_check
    CHECK (role IN (
        'admin', 'manager', 'technician',
        'dispatcher', 'sales', 'finance', 'read_only'
    ));
