-- MAPPS-1099 Phase 2b-rest: mapping tables between Mokosh identifiers and
-- the external invoice-issuer's own identifiers.
--
-- A delegated invoice carries three ids the local row never cared about:
-- the external customer (Xero `ContactID` / QuickBooks `CustomerRef.value`)
-- the invoice is billed to, the external product/item each line references
-- (Xero line.ItemCode or QuickBooks `SalesItemLineDetail.ItemRef.value`),
-- and the external organisation / realm the whole call is scoped to. The
-- customer and item mappings move with the tenant's own data and belong in
-- their own tables; the external organisation / realm sits on the
-- `integrations` row itself, next to the OAuth status.
--
-- Nothing writes these tables yet; the SPA mapping UI + the dispatch that
-- reads them land in Phase 2c (the follow-up to this PR). Shipping the
-- schema first keeps the write path's compile-time types stable so the
-- caller code lands against a schema that already exists, matching the
-- Phase 1 groundwork posture for `invoices.external_*`.
--
-- All three objects are strictly additive: a nullable column on
-- `integrations`, two new tables with their own CHECK + RLS, no backfill.
-- A rollback is a `DROP TABLE` + `ALTER TABLE ... DROP COLUMN`; existing
-- rows carry NULL for the new column and the local path keeps working.

ALTER TABLE integrations
    ADD COLUMN IF NOT EXISTS external_organisation_id text;

COMMENT ON COLUMN integrations.external_organisation_id IS
    'MAPPS-1099: Xero tenant_id (the organisation the OAuth consent selected) or QuickBooks realmId (the company file id). NULL for a provider that is not a delegated invoice issuer, and for a Xero/QuickBooks row connected before Phase 2b-rest landed; the Phase 2c reconnect flow backfills it on the next OAuth exchange.';

-- One Mokosh company maps to one external customer per provider. A tenant
-- that delegates to BOTH providers has two rows for the same company_id,
-- one per provider; the primary key `(tenant_id, provider, company_id)`
-- enforces that pair.
CREATE TABLE IF NOT EXISTS invoice_issuer_company_mappings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider text NOT NULL
        CHECK (provider IN ('xero', 'quickbooks')),
    company_id uuid NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    external_customer_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, company_id)
);

CREATE INDEX IF NOT EXISTS invoice_issuer_company_mappings_tenant_id_idx
    ON invoice_issuer_company_mappings (tenant_id);
CREATE INDEX IF NOT EXISTS invoice_issuer_company_mappings_lookup_idx
    ON invoice_issuer_company_mappings (tenant_id, provider, company_id);

ALTER TABLE invoice_issuer_company_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_issuer_company_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoice_issuer_company_mappings
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_issuer_company_mappings TO mokosh_app;

-- One Mokosh product maps to one external item per provider. Same shape
-- as the company mappings; a line that references a product with no
-- mapping fails the delegated issue at a well-known refusal rather than
-- silently sending the line to QBO without an `ItemRef`.
CREATE TABLE IF NOT EXISTS invoice_issuer_product_mappings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider text NOT NULL
        CHECK (provider IN ('xero', 'quickbooks')),
    product_id uuid NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    external_item_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, product_id)
);

CREATE INDEX IF NOT EXISTS invoice_issuer_product_mappings_tenant_id_idx
    ON invoice_issuer_product_mappings (tenant_id);
CREATE INDEX IF NOT EXISTS invoice_issuer_product_mappings_lookup_idx
    ON invoice_issuer_product_mappings (tenant_id, provider, product_id);

ALTER TABLE invoice_issuer_product_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_issuer_product_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoice_issuer_product_mappings
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_issuer_product_mappings TO mokosh_app;
