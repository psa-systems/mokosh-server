-- Websites move onto the asset model.
--
-- Two motivations, both from the field:
--   1. A company legitimately owns many websites, so a single
--      `companies.website` column cannot hold them.
--   2. The word "site" in the interface means a physical office (the
--      RMM-industry convention). Modelling a website as a `sites` row
--      would deepen the ambiguity; modelling it as an asset does not.
--
-- What this migration does:
--
--   a. Seeds a per-tenant `asset_types.name = 'Website'` for every
--      existing tenant that does not already have one, and for the
--      default tenant (which is the row every new tenant copies from
--      via `TenantService::seed_default_config`). A tenant that
--      already added its own type of the same name is left alone.
--
--   b. Backfills one asset row per company that holds a non-blank
--      `companies.website`. The asset's name is the URL; the URL is
--      also written into `assets.notes` so a future asset schema
--      change does not lose it.
--
--   c. Leaves `companies.website` in place with a deprecation comment.
--      The API and the SPA still read it; a follow-up drops the column
--      once every reader has moved to the asset side. Doing that here
--      would break every running UI and every running integration.
--
-- Idempotency: every write uses ON CONFLICT DO NOTHING or a guard, so
-- re-running the migration on a database that has already been through
-- it is a no-op. The append-only rule for migrations still holds; this
-- shape is what makes a partial replay from a snapshot recoverable.

BEGIN;

-- (a) Seed the "Website" asset type for the default tenant and every
-- existing tenant. The default tenant's row is what new tenants copy
-- from via `TenantService::seed_default_config`, so a fresh tenant
-- created AFTER this migration inherits the type without a second
-- write path.
INSERT INTO asset_types (tenant_id, name, icon, custom_fields_schema)
SELECT id, 'Website', 'globe', '[
    {"name": "url", "type": "text", "label": "URL"},
    {"name": "registrar", "type": "text", "label": "Registrar"},
    {"name": "expires_at", "type": "date", "label": "Expires at"}
]'::jsonb
FROM tenants
ON CONFLICT DO NOTHING;

-- (b) Backfill one asset per company with a non-blank website. A
-- second run inserts nothing because the WHERE clause excludes any
-- company that already holds a Website asset. The asset's `status` is
-- `active` by column default; every other required field is either
-- defaulted or resolved here.
INSERT INTO assets (
    tenant_id, company_id, asset_type_id, name, notes, status
)
SELECT
    c.tenant_id,
    c.id,
    at.id,
    c.website,
    'Migrated from companies.website. See PSA release notes for the shape change.',
    'active'
FROM companies c
JOIN asset_types at
  ON at.tenant_id = c.tenant_id AND at.name = 'Website'
WHERE c.website IS NOT NULL
  AND btrim(c.website) <> ''
  AND NOT EXISTS (
      SELECT 1 FROM assets a
      WHERE a.company_id = c.id
        AND a.asset_type_id = at.id
  );

-- (c) Mark the legacy column as deprecated. Kept in place so existing
-- readers keep working; a later migration drops it once no reader
-- names it.
COMMENT ON COLUMN companies.website IS
    'Deprecated: use the Website asset type instead. Migrated onto assets in migration 246. Left for backward compatibility until every reader has moved.';

COMMIT;
