-- MAPPS-1217 (ports MAPPS-877 commit 0a9e5525): promote `read_only`
-- to a first-class `users.role` value, plus parity on every other
-- table whose CHECK constraint lists the same role vocabulary.
--
-- BUNYIP-674's PMS-1162 grant-role vocabulary already includes
-- `read_only` (`admin | manager | technician | finance | read_only`),
-- but mokosh's own `users.role` CHECK constraint never listed it, so
-- `map_grant_role` (`src/modules/auth/mokosh_bunyip_grants.rs`)
-- projected `read_only` grantees onto `technician`. That grant of
-- technician-level WRITE access on a workspace the grantee is meant
-- to view read-only is the module-doc "deliberately over-privileged
-- for now" bullet, deferred until the grant surface had testing
-- traffic. Round-three tester caught it (read_only viewer could
-- create companies, invoices, tickets).
--
-- Widens three CHECK constraints: `users.role` (migration 003),
-- `tenant_invitations.role` (migration 035), and
-- `tenant_memberships.role` (migration 157; the users -> identities
-- mirror trigger copies `users.role` into this column one-way per
-- PMS-1120, so a `read_only` user insert would fail the membership
-- CHECK without this widening).
--
-- No data migration is needed: no row can carry `read_only` today
-- because every one of these constraints refused it, so widening
-- the accepted set is purely additive. The `UserRole::ReadOnly`
-- variant lands in the same commit; every write path that used to
-- admit any authenticated user now gates on `caller.role.can_write()`
-- and refuses a `ReadOnly` caller via the `require_write_for_mutations`
-- middleware on `/api/v1/*` (see `src/modules/auth/middleware.rs`).

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

ALTER TABLE tenant_memberships
    DROP CONSTRAINT IF EXISTS tenant_memberships_role_check;

ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_role_check
    CHECK (role IN (
        'super_admin', 'admin', 'manager', 'technician',
        'dispatcher', 'sales', 'finance', 'read_only'
    ));
