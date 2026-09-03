-- PMS-955: a product catalog a contract item and an invoice line can reference.
--
-- Products have been billable for as long as `invoice_lines.line_type` has
-- allowed `'product'`, but only as free text: a name, a description and a price
-- typed in per document. Nothing shared a price, nothing carried a SKU, and the
-- same product sold to two clients was two unrelated rows that could silently
-- disagree. This is the price list that fixes that, and nothing more.
--
-- It is NOT an inventory system. There is no quantity on hand, no purchasing
-- and no vendor: that is PMS-821's territory. And it introduces no second
-- pricing concept beside `rate_cards`, which prices LABOUR by work type and by
-- the hour; a product is a thing sold by the unit, which is a different axis.

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Optional, because plenty of MSPs sell things that have no part number,
    -- and unique when present (see the partial index below).
    sku VARCHAR(64),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    unit_price DECIMAL(12, 2) NOT NULL,
    -- What one of it is: 'each', 'hour', 'month', 'user'. Free text rather than
    -- a CHECK, because the list an MSP needs is theirs and a constraint here
    -- would be a migration every time they sell something new.
    unit VARCHAR(30) NOT NULL DEFAULT 'each',
    is_taxable BOOLEAN NOT NULL DEFAULT TRUE,
    -- Deactivation is the retirement path. A product that has ever been sold
    -- cannot be deleted (the FKs below refuse it), and should not be: the
    -- documents that sold it still name it.
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_products_tenant ON products (tenant_id);
CREATE INDEX idx_products_active ON products (tenant_id, is_active);

-- Identity, enforced rather than hoped for. A partial index because `sku` is
-- optional and a plain UNIQUE would let exactly one row omit it.
CREATE UNIQUE INDEX idx_products_sku ON products (tenant_id, sku) WHERE sku IS NOT NULL;

-- Case-insensitive name uniqueness, for the same reason companies have it
-- (PMS-400): two catalog rows both reading "Microsoft 365 Business Standard"
-- with different prices is precisely the confusion this table exists to remove,
-- and it is invisible on screen.
CREATE UNIQUE INDEX idx_products_name ON products (tenant_id, lower(name));

-- The reference. Nullable on both, because every existing row is free text and
-- migrations are immutable, so a backfill cannot invent a link that was never
-- made. No `ON DELETE` clause on either: a plain reference already refuses to
-- drop a product some document still names, which is the behaviour wanted.
ALTER TABLE invoice_lines ADD COLUMN product_id UUID REFERENCES products(id);
ALTER TABLE contract_items ADD COLUMN product_id UUID REFERENCES products(id);

CREATE INDEX idx_invoice_lines_product ON invoice_lines (product_id) WHERE product_id IS NOT NULL;
CREATE INDEX idx_contract_items_product ON contract_items (product_id) WHERE product_id IS NOT NULL;

-- The price stays ON the line, which `invoice_lines.unit_price` already does.
-- Stated here because it is the load-bearing half of the design: a line must
-- never read through to the catalog at render time, or last year's invoice
-- re-prices itself the day somebody edits a product, and an issued invoice is
-- immutable (PMS-953).

-- Fail-closed RLS, the shape every tenant-scoped table carries since
-- 038_rls_fail_closed.sql and that `tests/rls_coverage.rs` enforces.
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE products FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON products;
CREATE POLICY tenant_isolation ON products
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
