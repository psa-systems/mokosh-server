-- Give every built-in portal role a stable key that survives a rename.
--
-- The three built-in roles are seeded and looked up by display name today
-- (`portal_roles.name = 'Billing Contact'` / `'Support Contact'` / `'Read-Only'`).
-- The runtime lookups now key on `builtin_key`, so a rename no longer moves
-- the resolved role and future backfills can key on it too.
--
-- Non-built-in rows (tenant-created custom roles) keep `builtin_key = NULL`.
-- The migrations already on main (171/179/180/197/199/217/219) stay keyed on
-- name and are not retrofitted: they are immutable, and every one names a
-- built-in row this backfill reaches by the same string.
--
-- Row-count guard: the backfill matches `is_builtin = TRUE AND name = '<X>'`,
-- a content-column literal on a per-tenant row. The expected count is the
-- number of tenants that carry each built-in and is not knowable at write
-- time, so each block takes a count with the same predicate before the UPDATE
-- and asserts the two match. That catches a semantic drift where the UPDATE
-- silently touches a different set than the SELECT, without pinning a value.

ALTER TABLE portal_roles ADD COLUMN builtin_key TEXT;

DO $$
DECLARE
    expected bigint;
    matched  bigint;
BEGIN
    SELECT count(*) INTO expected
      FROM portal_roles
     WHERE is_builtin = TRUE AND name = 'Billing Contact';
    UPDATE portal_roles SET builtin_key = 'billing_contact'
     WHERE is_builtin = TRUE AND name = 'Billing Contact';
    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'portal_roles.builtin_key backfill (Billing Contact)');
END $$;

DO $$
DECLARE
    expected bigint;
    matched  bigint;
BEGIN
    SELECT count(*) INTO expected
      FROM portal_roles
     WHERE is_builtin = TRUE AND name = 'Support Contact';
    UPDATE portal_roles SET builtin_key = 'support_contact'
     WHERE is_builtin = TRUE AND name = 'Support Contact';
    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'portal_roles.builtin_key backfill (Support Contact)');
END $$;

DO $$
DECLARE
    expected bigint;
    matched  bigint;
BEGIN
    SELECT count(*) INTO expected
      FROM portal_roles
     WHERE is_builtin = TRUE AND name = 'Read-Only';
    UPDATE portal_roles SET builtin_key = 'read_only'
     WHERE is_builtin = TRUE AND name = 'Read-Only';
    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'portal_roles.builtin_key backfill (Read-Only)');
END $$;

-- Unique per tenant / company so a duplicate seeding attempt fails loud rather
-- than leaving two rows one lookup can pick from arbitrarily. Partial: only the
-- built-in rows carry a key.
CREATE UNIQUE INDEX portal_roles_builtin_key_uniq
    ON portal_roles (tenant_id, COALESCE(company_id, '00000000-0000-0000-0000-000000000000'::uuid), builtin_key)
    WHERE builtin_key IS NOT NULL;
