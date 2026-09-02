-- PMS-953: credit notes, the correction path an issued invoice never had.
--
-- PMS-38 froze an invoice at `sent` and said "correction goes through a credit
-- note, which is out of scope for this commit". PMS-39 said the same about a
-- posted payment. The freezing half shipped and the correcting half did not, so
-- what exists today is not immutability with a correction path, it is a dead
-- end: `update_invoice` refuses every edit once the invoice is frozen, and
-- nothing anywhere writes `void` or `written_off`, which makes them statuses the
-- model knows and no code path can reach. An MSP that sends a wrong invoice has
-- no move inside the product.
--
-- A credit note leaves the original standing and states the correction as its
-- own document, because the customer holds the original: an MSP that rewrites
-- an issued invoice makes its own records disagree with the copy in the client's
-- inbox, which is the disagreement an MSP loses. Same reasoning PMS-931 applied
-- to an emailed ticket note, and it is what will make a stored PDF (PMS-910) and
-- snapshotted branding (PMS-911) coherent: the document that was sent stays the
-- document that was sent.

CREATE TABLE credit_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    credit_note_number VARCHAR(50) NOT NULL,
    company_id UUID NOT NULL REFERENCES companies(id),
    -- NOT NULL: a credit note in this release always corrects one invoice. A
    -- standing account credit with no invoice is a different document with a
    -- different balance rule, and making the column nullable now would let one
    -- be written before that rule exists.
    invoice_id UUID NOT NULL REFERENCES invoices(id),
    -- Issued or void, and nothing else. A credit note is never EDITED, for the
    -- same reason the invoice it corrects is not; voiding is a state change that
    -- leaves every amount and every line exactly as issued. Without this the fix
    -- for a wrong invoice would itself be uncorrectable, which is the dead end
    -- this migration exists to remove, one level up.
    status VARCHAR(20) NOT NULL DEFAULT 'issued' CHECK (status IN ('issued', 'void')),
    issue_date DATE NOT NULL,
    -- Why the credit was raised. Free text, and the thing an auditor reads
    -- first, so it is required rather than a nullable afterthought.
    reason TEXT NOT NULL,
    subtotal DECIMAL(12, 2) NOT NULL DEFAULT 0,
    tax_amount DECIMAL(12, 2) NOT NULL DEFAULT 0,
    total DECIMAL(12, 2) NOT NULL DEFAULT 0,
    currency VARCHAR(3) DEFAULT 'USD',
    notes TEXT,
    -- The author survives their own deactivation: the record of who credited a
    -- customer must not vanish because somebody left. SET NULL, like
    -- `kb_article_attachments.uploaded_by_id`.
    created_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    voided_at TIMESTAMPTZ,
    voided_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, credit_note_number),
    -- A zero or negative credit note is not a correction, it is a no-op row that
    -- would still consume a number in a gapless series. `payments.amount` earns
    -- its positivity check the same way (052_payments_amount_positive.sql).
    CONSTRAINT credit_notes_total_positive CHECK (total > 0)
);

CREATE INDEX idx_credit_notes_tenant ON credit_notes (tenant_id);
CREATE INDEX idx_credit_notes_invoice ON credit_notes (tenant_id, invoice_id);
CREATE INDEX idx_credit_notes_company ON credit_notes (tenant_id, company_id);

-- Its own series, not a continuation of the invoice numbers: a credit note is a
-- different document and an accountant reading "INV-0042" expects an invoice.
-- Same shape as `invoice_sequences` so `next_credit_note_number` can be the same
-- gapless seed-or-bump inside the caller's transaction (PMS-194).
CREATE TABLE credit_note_sequences (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    last_number INTEGER NOT NULL DEFAULT 0,
    prefix VARCHAR(10) DEFAULT 'CN-'
);

-- Lines carry no `tenant_id`, exactly like `invoice_lines`: they are reachable
-- only through their parent, which is tenant-scoped, and adding the column would
-- create a second place for the two to disagree.
CREATE TABLE credit_note_lines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    credit_note_id UUID NOT NULL REFERENCES credit_notes(id) ON DELETE CASCADE,
    line_type VARCHAR(20) NOT NULL DEFAULT 'service' CHECK (line_type IN ('service', 'product', 'time_entry', 'mileage', 'adjustment', 'tax', 'discount')),
    description TEXT NOT NULL,
    quantity DECIMAL(10, 2) NOT NULL DEFAULT 1,
    unit_price DECIMAL(12, 2) NOT NULL,
    total DECIMAL(12, 2) NOT NULL,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credit_note_lines_note ON credit_note_lines (credit_note_id);

-- The invoice's side of the balance. Derived, never authored: every write goes
-- through the one recompute that already owns `amount_paid`, so the two figures
-- cannot be updated by different code with different rules.
ALTER TABLE invoices ADD COLUMN amount_credited DECIMAL(12, 2) NOT NULL DEFAULT 0;

-- Fail-closed RLS, the shape every tenant-scoped table carries since
-- 038_rls_fail_closed.sql and that `tests/rls_coverage.rs` enforces.
ALTER TABLE credit_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE credit_notes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON credit_notes;
CREATE POLICY tenant_isolation ON credit_notes
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

ALTER TABLE credit_note_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE credit_note_sequences FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON credit_note_sequences;
CREATE POLICY tenant_isolation ON credit_note_sequences
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
