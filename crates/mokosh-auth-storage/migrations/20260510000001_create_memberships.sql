-- Many-to-many between users and tenants. A user can belong to multiple
-- tenants (their own personal tenant from self-signup, plus any org
-- tenants they have been invited into). The existing
-- mokosh_auth.users.tenant_id stays as a "home" pointer for now; the
-- source of truth for access is this table.
--
-- Rolls forward by:
--   1. Creating the table.
--   2. Backfilling one membership per existing active user.
--   3. Promoting the email index from non-unique to UNIQUE so a single
--      person cannot have two accounts under different tenants. The
--      old per-tenant unique index stays for fast lookups by
--      (tenant_id, email); the new global one is the access-control
--      invariant.
--
-- See docs/mokosh-auth/10-memberships-and-self-signup.md (Phase 1).

-- 1. memberships table.
CREATE TABLE mokosh_auth.memberships (
    user_id      UUID NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id    UUID NOT NULL REFERENCES public.tenants(id)    ON DELETE CASCADE,
    role         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    joined_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, tenant_id),

    CONSTRAINT memberships_role_chk
        CHECK (role IN ('admin','manager','finance','member','readonly')),
    CONSTRAINT memberships_status_chk
        CHECK (status IN ('active','suspended'))
);

-- The PK already covers (user_id, tenant_id); these accelerate the
-- two single-column lookup directions ("all memberships for user X",
-- "all memberships in tenant Y").
CREATE INDEX memberships_by_user   ON mokosh_auth.memberships(user_id);
CREATE INDEX memberships_by_tenant ON mokosh_auth.memberships(tenant_id);

-- 2. Backfill from the existing 1:1 mokosh_auth.users.tenant_id. Role
-- copies straight across (memberships and users use the same enum).
-- Status maps active->active, anything else->suspended (pending,
-- suspended, and deleted-but-not-yet-cleared users all collapse to
-- "no live access" in the membership model).
INSERT INTO mokosh_auth.memberships (user_id, tenant_id, role, status, joined_at)
SELECT
    u.id,
    u.tenant_id,
    u.role,
    CASE u.status WHEN 'active' THEN 'active' ELSE 'suspended' END,
    u.created_at
FROM mokosh_auth.users u
WHERE u.deleted_at IS NULL;

-- 3. Promote the email index to UNIQUE globally (case-insensitive
-- because email is CITEXT). This makes "one account, one email" the
-- invariant the rest of the auth surface (federation, password
-- reset, future external IdPs) can rely on. The pre-existing per-
-- tenant unique index `users_tenant_email_idx` stays - it is no
-- longer load-bearing for uniqueness but is still the right index
-- for `find_by_email(tenant_id, email)`.
--
-- This CREATE will fail if duplicate emails exist across tenants.
-- Run this lookup before applying the migration on real data:
--
--   SELECT email, COUNT(*)
--   FROM mokosh_auth.users
--   WHERE deleted_at IS NULL
--   GROUP BY email
--   HAVING COUNT(*) > 1;
--
-- Resolve any matches (merge accounts, soft-delete one of them) before
-- deploying.
DROP INDEX IF EXISTS mokosh_auth.users_email_active_idx;

CREATE UNIQUE INDEX users_email_global
    ON mokosh_auth.users(email)
    WHERE deleted_at IS NULL;
