-- PMS-333: replace the free-text `invoices.payment_terms` column with a
-- tenant-scoped `payment_terms` lookup table so the MAPPS Settings hub
-- (MAPPS-170) can manage the option set per tenant and the invoice form can
-- offer a managed dropdown. Storage model is a normalized FK
-- (`invoices.payment_term_id -> payment_terms.id`) so terms are rename-safe.
--
-- Mirrors the project_types lookup (048): explicit RLS policy + updated_at
-- trigger (the 038/024 sweeps already ran, so a table created now must attach
-- both itself), the single-default partial unique index from PMS-323 (049),
-- and a per-tenant seed so copy_default_config can replicate to new tenants.
--
-- The legacy `invoices.payment_terms` string column is KEPT for one release
-- (create/read paths still write/return it); a follow-up release drops it once
-- clients read `payment_term_id`.

-- ============================================================================
-- 1. payment_terms lookup table.
-- ============================================================================
CREATE TABLE payment_terms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_payment_terms_tenant ON payment_terms(tenant_id);
-- One row per (tenant, name) so the backfill join and any name -> id
-- resolution are unambiguous.
CREATE UNIQUE INDEX idx_payment_terms_tenant_name ON payment_terms(tenant_id, name);

-- ============================================================================
-- 2. RLS: the table carries tenant_id, but the 038 fail-closed sweep already
-- ran, so a table created now needs its policy added explicitly (mirrors 048).
-- ============================================================================
ALTER TABLE payment_terms ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_terms FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON payment_terms
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- ============================================================================
-- 3. updated_at trigger (the 024/043 sweeps already ran; attach explicitly).
-- ============================================================================
DROP TRIGGER IF EXISTS update_payment_terms_updated_at ON payment_terms;
CREATE TRIGGER update_payment_terms_updated_at
    BEFORE UPDATE ON payment_terms
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 4. Seed a sensible default set for EVERY existing tenant, with net30 as the
-- single default. The per-tenant seed lets copy_default_config replicate them
-- to future tenants by copying the default tenant's rows. `net30` matches the
-- legacy column default so the backfill below links 'net30' invoices to it.
-- ============================================================================
INSERT INTO payment_terms (tenant_id, name, is_default, is_active, sort_order)
SELECT t.id, v.name, v.is_default, TRUE, v.sort_order
FROM tenants t
CROSS JOIN (VALUES
    ('due_on_receipt', FALSE, 1),
    ('net15', FALSE, 2),
    ('net30', TRUE, 3),
    ('net60', FALSE, 4)
) AS v(name, is_default, sort_order);

-- ============================================================================
-- 5. Backfill any DISTINCT existing free-text value that is not already in the
-- seeded set, per tenant, so no invoice is orphaned. These come in inactive
-- of the default flag (is_default FALSE) to preserve single-default.
-- ============================================================================
INSERT INTO payment_terms (tenant_id, name, is_default, is_active, sort_order)
SELECT DISTINCT i.tenant_id, i.payment_terms, FALSE, TRUE, 0
FROM invoices i
WHERE i.payment_terms IS NOT NULL
  AND i.payment_terms <> ''
  AND NOT EXISTS (
    SELECT 1 FROM payment_terms p
    WHERE p.tenant_id = i.tenant_id AND p.name = i.payment_terms
  );

-- ============================================================================
-- 6. Single-default-per-tenant DB guard (PMS-323 pattern). The seed gives each
-- tenant exactly one default (net30), so the index builds cleanly.
-- ============================================================================
CREATE UNIQUE INDEX idx_payment_terms_one_default ON payment_terms (tenant_id) WHERE is_default;

-- ============================================================================
-- 7. Add invoices.payment_term_id, backfill from the legacy string, index it.
-- Invoices with NULL/empty payment_terms keep payment_term_id NULL.
-- ============================================================================
ALTER TABLE invoices
    ADD COLUMN payment_term_id UUID REFERENCES payment_terms(id);

UPDATE invoices i
SET payment_term_id = p.id
FROM payment_terms p
WHERE p.tenant_id = i.tenant_id
  AND p.name = i.payment_terms;

CREATE INDEX idx_invoices_payment_term_id ON invoices(payment_term_id);
