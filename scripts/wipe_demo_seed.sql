-- Wipe first-visit demo-seed data from a tenant (PMS-239 / PMS-157).
--
-- WHY: in a Bunyip deployment every user JIT-lands in one shared tenant
-- (OIDC_DEFAULT_TENANT_ID; the at+jwt carries no tenant claim yet, docs §3.3),
-- so the demo company + contacts + tickets are visible to, and editable by,
-- every user in that tenant. The code now refuses to auto-seed that shared
-- tenant (see src/modules/seed/service.rs), but rows that were seeded BEFORE
-- the fix still need removing. This script does that.
--
-- The demo set is exactly: one company named 'Acme Corporation (Demo)', its
-- two contacts (Alice Anderson, Bob Baker), and three tickets - all tagged
-- 'demo'. Contacts/sites cascade on company delete; tickets do NOT (no
-- ON DELETE CASCADE in migrations/005_tickets.sql), so they are removed first.
--
-- USAGE (review before committing):
--   psql "$STAGING_DATABASE_URL" \
--     -v tenant_id="'00000000-0000-0000-0000-000000000001'" \
--     -f scripts/wipe_demo_seed.sql
--
-- The whole thing runs in a transaction and ends with ROLLBACK, so by default
-- it only PREVIEWS. After you have read the counts and confirmed they match the
-- demo data (and nothing real), change the final ROLLBACK to COMMIT and rerun.
--
-- Note: the `tenants.settings->>'demo_seeded'` flag is left set to 'true' on
-- purpose, so the tenant is never re-seeded.

\set ON_ERROR_STOP on

BEGIN;

-- Identify the demo companies for this tenant (id captured into a temp table so
-- the preview and the deletes target the exact same rows).
CREATE TEMP TABLE _demo_companies ON COMMIT DROP AS
SELECT id
FROM companies
WHERE tenant_id = :tenant_id
  AND name = 'Acme Corporation (Demo)'
  AND tags @> ARRAY['demo']::text[];

-- PREVIEW: what will be removed.
SELECT 'companies' AS entity, count(*) AS rows
FROM companies WHERE id IN (SELECT id FROM _demo_companies)
UNION ALL
SELECT 'contacts', count(*)
FROM contacts WHERE company_id IN (SELECT id FROM _demo_companies)
UNION ALL
SELECT 'tickets', count(*)
FROM tickets WHERE company_id IN (SELECT id FROM _demo_companies);

-- Tickets first (no cascade from companies), then the companies (contacts and
-- sites cascade via ON DELETE CASCADE).
DELETE FROM tickets WHERE company_id IN (SELECT id FROM _demo_companies);
DELETE FROM companies WHERE id IN (SELECT id FROM _demo_companies);

-- Safety default: PREVIEW ONLY. Change to COMMIT once the counts look right.
ROLLBACK;
