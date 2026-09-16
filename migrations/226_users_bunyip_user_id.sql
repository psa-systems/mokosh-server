-- BUNYIP-674 follow-up (JIT grantee placement, option B):
-- decouple `users.id` from the caller's Bunyip `sub` so ONE bunyip user
-- can appear in more than one Mokosh tenant. The owner path is
-- unchanged: for a user's own tenant, `users.id = sub` still holds,
-- because the backfill below seeds `bunyip_user_id` from `id`.
--
-- A GRANTEE gets a NEW users row in the granted tenant with a fresh
-- `id` (uuid_generate_v4) and `bunyip_user_id = sub`; the resolver on
-- the grant path looks the row up by (bunyip_user_id, tenant_id)
-- rather than by `id`. That keeps every existing FK on `users.id`
-- working - `user_sessions`, `api_keys`, audit_log, ticket
-- assignments, and so on all point at the specific row for that
-- (sub, tenant) placement, so a grantee's activity is scoped to the
-- granted tenant without leaking into their own.
--
-- The column is nullable for pre-migration rows (a users row created
-- before BUNYIP-673 has no Bunyip mirror by definition), but every
-- row on this migration's `main` gets it via the backfill. The
-- unique index is partial so a row without a mirror does not collide
-- with itself.
--
-- Why not a composite PK `(id, tenant_id)`: that would rewrite every
-- FK on users.id in the schema (user_sessions, api_keys, audit_log,
-- ticket_notes.author_id, calendar_events.owner_id, and about
-- twenty more) and every service call that resolves a user by id.
-- The additive column keeps the invariant "one row = one placement"
-- while giving the grant path a second lookup axis.

ALTER TABLE users ADD COLUMN bunyip_user_id UUID;

-- Backfill: every existing users row IS its bunyip sub (the PMS-172
-- resolver reads `WHERE id = sub`). Seed the column so the lookup by
-- `bunyip_user_id` returns the same row `id` does today; the grant
-- path can rely on the column being present for everything on main.
UPDATE users SET bunyip_user_id = id WHERE bunyip_user_id IS NULL;

-- One bunyip user, at most one users row per tenant. Partial so a
-- pre-migration row with `bunyip_user_id IS NULL` does not fail this
-- (there should be none after the backfill, but nothing forbids a
-- future manual insert from omitting the mirror).
CREATE UNIQUE INDEX idx_users_bunyip_tenant
    ON users (bunyip_user_id, tenant_id)
    WHERE bunyip_user_id IS NOT NULL;

-- Cross-tenant lookup (BUNYIP-674 grant resolver): find every tenant
-- one bunyip user is placed in. Partial for the same reason.
CREATE INDEX idx_users_bunyip_user_id
    ON users (bunyip_user_id)
    WHERE bunyip_user_id IS NOT NULL;
