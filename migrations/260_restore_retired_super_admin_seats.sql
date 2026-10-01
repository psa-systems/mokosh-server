-- PMS-1425: retiring the super_admin ROLE must not take away the person's SEAT.
--
-- Migration 162 (MAPPS-518) retired `users.role = 'super_admin'` by setting
-- those rows to `status = 'inactive'` with `password_hash`, `mfa_secret` and
-- `mfa_enabled` cleared, rather than deleting them, so ticket and note
-- attribution survived. That reasoning was right about attribution and wrong
-- about one thing it did not consider: on a bunyip-signed-in deployment that
-- `users` row is also the person's only seat in their tenant.
--
-- So `resolve_bunyip_caller` finds the existing placement, and
-- `ensure_principal_usable` refuses it because `status <> 'active'`. Every API
-- call answers 403 "Account is not active", for everyone who had ever been a
-- super-admin, indefinitely, and the message points at the person's account
-- rather than at a migration. Hit on nc-01 on 2026-09-29, the first upgrade
-- past 162 (v0.13.0 to v0.15.0): five rows retired in one batch, four of them
-- people who work here, one created as `super_admin` by a v0.13.0 bunyip
-- sign-in twenty-two minutes earlier. Production was repaired by hand; this is
-- so the next deployment to take the upgrade does not have to be.
--
-- 162 is immutable, so this demotes instead of editing it: the role goes to
-- `admin`, which is what the hand repair chose and what the person needs to use
-- their own tenant, and the credentials stay NULL because bunyip is the only
-- sign-in path for them and a NULL hash is what keeps MAPPS-498's mirror
-- fail-closed (`verify_password` refuses a missing hash rather than accepting a
-- mirrored write from a sibling tenant).
--
-- ## The guard, and what it deliberately cannot tell apart
--
-- The WHERE clause targets exactly the shape 162 leaves: inactive, still
-- `super_admin`, both credential columns NULL. An inactive row with a password
-- hash was deactivated by a person and is left alone; so is any other role.
--
-- What it cannot distinguish is a super-admin somebody deliberately deactivated
-- BEFORE 162 ran, because 162 then cleared that row's credentials too and made
-- it identical to the ones it retired. This restores it. That is the deliberate
-- choice: of the two ways to be wrong, handing back access to someone who left
-- is visible and fixable by an admin in one click, while locking out everyone
-- who still works here is neither, and it reads as the product being broken. An
-- admin deactivating a departed colleague again after the upgrade is the
-- intended follow-up, and it belongs in the release notes.
--
-- ## Why this counts rather than asserts
--
-- No `mokosh_assert_content_rows_matched` (migration 208, PMS-1117). That
-- helper exists for a guarded UPDATE whose expected count is knowable, and this
-- one's is not: it is however many super-admins a given deployment happened to
-- have, which is five on nc-01, zero on a fresh database, and zero again on any
-- deployment already repaired by hand. Asserting a number here would fail the
-- migration, and therefore the boot, on the deployments that need it least. A
-- NOTICE with the count is the honest signal: an operator reading the upgrade
-- log sees how many seats came back, and zero is a legitimate answer.
--
-- Idempotent: a second run finds the rows already `active` and matches none.
--
-- One correction while here, since 162's own text cannot be edited: its comment
-- cites "migrations 131 + 132" for the platform-admin tables. They are created
-- and backfilled by 160 and 161. The same stale pair was in `src/db/mod.rs` and
-- is fixed in this change.

DO $$
DECLARE
    restored bigint;
BEGIN
    UPDATE users
    SET status = 'active',
        role = 'admin',
        updated_at = NOW()
    WHERE role = 'super_admin'
      AND status = 'inactive'
      AND password_hash IS NULL
      AND mfa_secret IS NULL;
    GET DIAGNOSTICS restored = ROW_COUNT;

    IF restored > 0 THEN
        RAISE NOTICE
            'PMS-1425: restored % tenant seat(s) retired by migration 162; each is now role=admin with no stored credential, so bunyip remains the only sign-in path. Deactivate anyone who has left.',
            restored;
    END IF;
END $$;
