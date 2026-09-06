-- MAPPS-518 (MAPPS-513 stage B): retire the super_admin `users` role.
--
-- The platform super-admin persona now lives exclusively in
-- `platform_admins` (see migrations 131 + 132 which create the table and
-- backfill from these rows). No handler still honours `users.role =
-- 'super_admin'` (`RequireSuperAdmin` was replaced with
-- `RequirePlatformAdmin` on every gate; see `modules/platform/routes.rs`).
--
-- The migration originally shipped `DELETE FROM users WHERE role =
-- 'super_admin'`. That works on a fresh dev database where the super-admin
-- owns nothing, but a deployed staging/production super-admin has usually
-- created tickets, ticket notes, saved reports, form request tokens, and
-- ticket templates — each of those tables carries a `NOT NULL REFERENCES
-- users(id)` FK with no `ON DELETE` clause, so the default `NO ACTION`
-- fires and every migration attempt aborts:
--
--     update or delete on table "users" violates foreign key constraint
--     "tickets_created_by_id_fkey" on table "tickets"
--
-- We can't NULL those columns (they are NOT NULL) and we can't cascade
-- (would lose the row entirely). Instead: strip the credential columns
-- and mark the row inactive. That preserves ticket / note / report
-- attribution while closing the two problems the DELETE existed to
-- close:
--
--   * privilege: the users.role value is functionally inert (see above).
--     `ensure_principal_usable` refuses any principal whose `status !=
--     'active'`, so an accidental future gate on the role still can't
--     let the row in.
--   * MAPPS-498 identities-mirror path (the "resend welcome email on
--     tenant Test also reset my super-admin password" bug): with
--     `password_hash = NULL` on the users row, no credential can be
--     mirrored TO here from an identity write — verify_password fails
--     closed on a missing hash and the login path returns 401 rather
--     than accepting a mirrored write from a sibling tenant.
--
-- Idempotent: a re-run finds the rows already at status='inactive' with
-- NULL credentials and updates nothing.

UPDATE users
SET status = 'inactive',
    password_hash = NULL,
    mfa_secret = NULL,
    mfa_enabled = FALSE,
    updated_at = NOW()
WHERE role = 'super_admin'
  AND (
    status <> 'inactive'
    OR password_hash IS NOT NULL
    OR mfa_secret IS NOT NULL
    OR mfa_enabled = TRUE
  );
