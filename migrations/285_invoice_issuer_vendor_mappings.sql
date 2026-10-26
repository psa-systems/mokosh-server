-- MAPPS-1155: which vendor a Mokosh vendor is in the provider's own list.
--
-- A bill is an obligation to a VENDOR, so pushing one names a vendor over
-- there the way pushing an invoice names a customer. `invoice_issuer_company
-- _mappings` cannot carry it: that table's `company_id` is a foreign key into
-- `companies`, and a vendor is a row in `vendors` (migration 279). One table
-- with a nullable company_id and a nullable vendor_id would be two tables
-- wearing a discriminator, and every read would have to say which half it
-- meant.
--
-- The shape is migration 282's, deliberately: same provider CHECK, same
-- uniqueness per (tenant, provider, subject), same fail-closed RLS. A second
-- shape for the same job is a second thing to get wrong.
--
-- PMS-1265: granted to `mokosh_app`, the role that serves.

CREATE TABLE IF NOT EXISTS invoice_issuer_vendor_mappings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider text NOT NULL
        CHECK (provider IN ('xero', 'quickbooks')),
    vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    -- Xero's ContactID (a uuid) or QuickBooks' VendorRef value (numeric, as
    -- a string). Text for the same reason the customer column is: the two
    -- providers do not agree on the shape and neither is ours to parse.
    external_vendor_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, vendor_id)
);

CREATE INDEX IF NOT EXISTS invoice_issuer_vendor_mappings_tenant_id_idx
    ON invoice_issuer_vendor_mappings (tenant_id);

ALTER TABLE invoice_issuer_vendor_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_issuer_vendor_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoice_issuer_vendor_mappings
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_issuer_vendor_mappings TO mokosh_app;
