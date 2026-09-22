-- Give every built-in portal role a stable key that survives a rename.
--
-- The three built-in roles are seeded and looked up by display name today
-- (`portal_roles.name = 'Billing Contact'` / `'Support Contact'` / `'Read-Only'`).
-- The CRUD surface (`PortalRoleService::update_role`) already blocks renaming a
-- built-in row, so the display name IS the identifier by convention. A single
-- rename by an admin who reached the row through another path (a database
-- write, a future migration) would flip every lookup on the fly. `builtin_key`
-- names the row by intent instead of by display, so a rename no longer moves
-- the lookup and future backfills can key on it.
--
-- Non-built-in rows (tenant-created custom roles) keep `builtin_key = NULL`.
-- The migrations already on main (171/179/180/197/199/217/219) stay keyed on
-- name and are not retrofitted: they are immutable, and every one names a
-- built-in row this backfill reaches by the same string.
ALTER TABLE portal_roles ADD COLUMN builtin_key TEXT;

UPDATE portal_roles SET builtin_key = 'billing_contact'
    WHERE is_builtin = TRUE AND name = 'Billing Contact';
UPDATE portal_roles SET builtin_key = 'support_contact'
    WHERE is_builtin = TRUE AND name = 'Support Contact';
UPDATE portal_roles SET builtin_key = 'read_only'
    WHERE is_builtin = TRUE AND name = 'Read-Only';

-- Unique per tenant / company so a duplicate seeding attempt fails loud rather
-- than leaving two rows one lookup can pick from arbitrarily. Partial: only the
-- built-in rows carry a key.
CREATE UNIQUE INDEX portal_roles_builtin_key_uniq
    ON portal_roles (tenant_id, COALESCE(company_id, '00000000-0000-0000-0000-000000000000'::uuid), builtin_key)
    WHERE builtin_key IS NOT NULL;
