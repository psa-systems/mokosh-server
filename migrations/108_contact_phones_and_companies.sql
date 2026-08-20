-- PMS-806: a contact carries an ordered list of typed phone numbers and links
-- to any number of companies, one of which is primary.
--
-- `contacts.phone` / `mobile` / `fax` / `company_id` stay on the table and stay
-- readable, but they become MAINTAINED MIRRORS of these two child tables: the
-- service recomputes them from the child rows inside the same transaction as
-- every create and update (`ContactService::recompute_contact_mirrors`). This
-- is a deliberate denormalization, not deferred work: it is what keeps every
-- existing query, index, seed fixture, portal lookup and the current SPA
-- working unchanged while the SPA catches up (MAPPS-481).
--
-- Mirror rule, in one place:
--   phone      = the number of the primary phone entry
--   mobile     = the first 'mobile'-type entry
--   fax        = the first 'fax'-type entry
--   company_id = the company of the primary link, NULL when there are no links

-- ============================================================================
-- 1. contact_phones
-- ============================================================================
CREATE TABLE contact_phones (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    phone_type VARCHAR(20) NOT NULL DEFAULT 'other'
        CHECK (phone_type IN ('mobile', 'work', 'home', 'fax', 'other')),
    number VARCHAR(50) NOT NULL,
    extension VARCHAR(20),
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contact_phones_contact ON contact_phones(tenant_id, contact_id, sort_order);
CREATE UNIQUE INDEX idx_contact_phones_one_primary ON contact_phones(contact_id) WHERE is_primary;

-- ============================================================================
-- 2. contact_companies
-- ============================================================================
CREATE TABLE contact_companies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    -- Role at THIS company. A contractor is "Consultant" at one client and
    -- "IT Director" at another; contacts.title stays the person's default.
    title VARCHAR(100),
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (contact_id, company_id)
);

CREATE INDEX idx_contact_companies_company ON contact_companies(tenant_id, company_id);
CREATE UNIQUE INDEX idx_contact_companies_one_primary ON contact_companies(contact_id) WHERE is_primary;

-- ============================================================================
-- 3. RLS: the 024 / 038 fail-closed sweeps already ran, so a table created now
-- declares its own policy (mirrors 101_form_request_tokens.sql).
-- ============================================================================
ALTER TABLE contact_phones ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_phones FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_phones
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

ALTER TABLE contact_companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_companies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_companies
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- 4. updated_at triggers (the 024 / 043 sweeps already ran; attach explicitly).
-- ============================================================================
DROP TRIGGER IF EXISTS update_contact_phones_updated_at ON contact_phones;
CREATE TRIGGER update_contact_phones_updated_at
    BEFORE UPDATE ON contact_phones
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_contact_companies_updated_at ON contact_companies;
CREATE TRIGGER update_contact_companies_updated_at
    BEFORE UPDATE ON contact_companies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 5. Backfill from the existing scalar columns.
-- ============================================================================
-- `contacts.phone` is the primary entry, typed 'work'; mobile and fax follow in
-- that order. Only `phone` is flagged primary, so a contact that today has only
-- a mobile keeps `contacts.phone = NULL` once the mirror rule runs over it.
INSERT INTO contact_phones (tenant_id, contact_id, phone_type, number, is_primary, sort_order)
SELECT c.tenant_id, c.id, 'work', c.phone, TRUE, 0
FROM contacts c
WHERE c.phone IS NOT NULL AND c.phone <> '';

INSERT INTO contact_phones (tenant_id, contact_id, phone_type, number, is_primary, sort_order)
SELECT c.tenant_id, c.id, 'mobile', c.mobile, FALSE, 1
FROM contacts c
WHERE c.mobile IS NOT NULL AND c.mobile <> '';

INSERT INTO contact_phones (tenant_id, contact_id, phone_type, number, is_primary, sort_order)
SELECT c.tenant_id, c.id, 'fax', c.fax, FALSE, 2
FROM contacts c
WHERE c.fax IS NOT NULL AND c.fax <> '';

INSERT INTO contact_companies (tenant_id, contact_id, company_id, title, is_primary)
SELECT c.tenant_id, c.id, c.company_id, c.title, TRUE
FROM contacts c
WHERE c.company_id IS NOT NULL;
