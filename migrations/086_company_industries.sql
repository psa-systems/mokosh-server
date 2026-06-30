-- PMS-601: promote the company "Industry" suggestion list from a hardcoded
-- frontend constant (mokosh-apps COMPANY_INDUSTRIES) to a tenant-scoped,
-- admin-editable lookup, so the Settings hub can curate the option set per
-- tenant without a code change. Follows the 048_project_types_lookup pattern.
--
-- Industry stays a free-text column on `companies` (PMS-582): this lookup only
-- feeds the combobox's suggestions, it does NOT convert companies.industry to a
-- foreign key. So there is no backfill of an FK column here.

-- ============================================================================
-- 1. company_industries lookup table.
-- ============================================================================
CREATE TABLE company_industries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_company_industries_tenant ON company_industries(tenant_id);
-- One canonical row per name per tenant, case-insensitive: the whole point is
-- to stop "IT" / "I.T." / "Information Technology" splitting into three rows.
CREATE UNIQUE INDEX idx_company_industries_tenant_name
    ON company_industries(tenant_id, lower(name));

-- ============================================================================
-- 2. RLS: the 038 fail-closed sweep already ran, so a table created now needs
-- its policy added explicitly (mirrors 048 / how 041 covered late tables).
-- ============================================================================
ALTER TABLE company_industries ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_industries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON company_industries
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- ============================================================================
-- 3. updated_at trigger (the 024/043 sweeps already ran; attach explicitly).
-- ============================================================================
DROP TRIGGER IF EXISTS update_company_industries_updated_at ON company_industries;
CREATE TRIGGER update_company_industries_updated_at
    BEFORE UPDATE ON company_industries
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 4. Seed the canonical defaults for EVERY existing tenant. The per-tenant
-- seed lets copy_default_config replicate them to future tenants by copying the
-- seed tenant's rows (which this statement also populates).
-- ============================================================================
INSERT INTO company_industries (tenant_id, name)
SELECT t.id, v.name
FROM tenants t
CROSS JOIN (VALUES
    ('Accounting'),
    ('Agriculture'),
    ('Automotive'),
    ('Banking'),
    ('Biotechnology'),
    ('Construction'),
    ('Consulting'),
    ('Education'),
    ('Energy & Utilities'),
    ('Engineering'),
    ('Entertainment & Media'),
    ('Finance'),
    ('Food & Beverage'),
    ('Government'),
    ('Healthcare'),
    ('Hospitality'),
    ('Information Technology'),
    ('Insurance'),
    ('Legal'),
    ('Manufacturing'),
    ('Marketing & Advertising'),
    ('Nonprofit'),
    ('Pharmaceuticals'),
    ('Real Estate'),
    ('Retail'),
    ('Telecommunications'),
    ('Transportation & Logistics'),
    ('Travel & Tourism'),
    ('Wholesale')
) AS v(name)
ON CONFLICT DO NOTHING;
