-- PMS-413: tenant "own company" for general / overhead time logging.
--
-- Establishes a per-tenant internal company so a general time entry (no
-- customer to bill) has a stable, real company_id to attribute overhead time
-- to. MAPPS-243 sends company_id = current_user.own_company_id for such
-- entries. This migration does BOTH the schema change and the one-time
-- backfill, and is idempotent: re-running it is a no-op (it only creates and
-- sets where own_company_id is still NULL).

-- 1. Allow the new `internal` company_type. Drop + re-add the CHECK so the
--    constraint name stays stable and the migration is safe to re-run.
ALTER TABLE companies DROP CONSTRAINT IF EXISTS companies_company_type_check;
ALTER TABLE companies
    ADD CONSTRAINT companies_company_type_check
    CHECK (company_type IN ('client', 'prospect', 'vendor', 'partner', 'internal'));

-- 2. Point each tenant at its own company. Nullable FK so the column can be
--    added without an immediate value, then backfilled below.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS own_company_id UUID REFERENCES companies(id);

-- 3. Exempt internal own-companies from the per-tenant duplicate-name unique
--    index (PMS-400, `057_companies_tenant_name_unique.sql`). That rule is for
--    customer companies; the own-company is a system row named after the
--    tenant and may legitimately share a name with an existing client (or with
--    the tenant's own name as it appears in the companies list). Without this,
--    the backfill below fails with a unique violation on any tenant that
--    already holds a company named like the tenant, aborting the migration and
--    crash-looping the server. Recreate the index as a partial unique index.
DROP INDEX IF EXISTS idx_companies_tenant_name_unique;
CREATE UNIQUE INDEX idx_companies_tenant_name_unique
    ON companies (tenant_id, lower(btrim(name)))
    WHERE company_type <> 'internal';

-- 4. Backfill: create one `internal` own-company per tenant that still lacks
--    one, named after the tenant, and link it. Guarded on own_company_id IS
--    NULL so a second run inserts nothing and updates nothing.
WITH new_own AS (
    INSERT INTO companies (tenant_id, name, company_type, status)
    SELECT t.id, t.name, 'internal', 'active'
    FROM tenants t
    WHERE t.own_company_id IS NULL
    RETURNING id, tenant_id
)
UPDATE tenants t
SET own_company_id = n.id,
    updated_at = NOW()
FROM new_own n
WHERE t.id = n.tenant_id
  AND t.own_company_id IS NULL;
