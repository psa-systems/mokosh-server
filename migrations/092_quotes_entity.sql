-- PMS-671 (phase 1 of the PMS-670 Quotes epic): promote the deliberate
-- `quotes` stub from 078 into the real sales entity, and add the
-- `quote_lines` child table.
--
-- 078 shipped `quotes` purely so the PMS-470 polymorphic approvals routes
-- had a parent row to existence-check against (`assert_parent_exists`).
-- Its own header says the richer sales workflow is its own follow-up and
-- that it is "intentionally NOT trying to be the final shape". This is
-- that follow-up. 078 is already applied on live databases and migrations
-- are immutable, so every change here is additive in a new file.
--
-- SAFETY NOTE on the NOT NULL adds below: no production code path inserts
-- into `quotes`. There is no quotes module yet; the only INSERT in the
-- tree is the integration test `tests/approvals_polymorphic.rs`. The table
-- is therefore empty in every real database, so promoting `company_id` to
-- NOT NULL cannot fail on existing data. It is written as add-then-enforce
-- rather than a single NOT NULL add so that a future backfill has an
-- obvious seam to slot into, and so the statement that would fail is the
-- one that names the reason.

-- ============================================================================
-- 1. Per-tenant quote numbering. Mirrors `invoice_sequences` (010_billing).
-- ============================================================================
CREATE TABLE quote_sequences (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    last_number INTEGER NOT NULL DEFAULT 0,
    prefix VARCHAR(10) DEFAULT 'QUO-'
);

-- ============================================================================
-- 2. Associations, scope, and the client sign-off record.
-- ============================================================================
ALTER TABLE quotes
    -- The client the quote is for. The single biggest omission in the stub:
    -- without it a quote cannot be shown to a customer, because the portal
    -- scopes every read by the signed-in contact's `company_id`.
    ADD COLUMN company_id UUID REFERENCES companies(id),
    -- Who receives the quote and who signs it off. Mirrors
    -- `invoices.billing_contact_id`.
    ADD COLUMN billing_contact_id UUID REFERENCES contacts(id),
    -- Human-facing identifier, allocated from `quote_sequences`. Nullable so
    -- the number is assigned by the service layer on create rather than
    -- being forced onto the pre-existing stub rows.
    ADD COLUMN quote_number VARCHAR(50),
    -- The scope-of-work body. The stub only has a one-line `summary`, which
    -- cannot hold a real statement of work.
    ADD COLUMN description TEXT,
    -- Quote expiry. Enforced at read time (a `sent` quote past this date is
    -- treated as expired and cannot be accepted), not by a scheduler.
    ADD COLUMN valid_until DATE,
    ADD COLUMN sent_at TIMESTAMPTZ,
    -- Client sign-off. Deliberately NOT modelled on `ticket_approvals`:
    -- that table constrains approvers to internal staff
    -- (`approver_user_id` XOR `approver_role`, both staff concepts), so it
    -- cannot express "the customer signed off". Internal approval stays on
    -- that surface; client acceptance lives here on the quote itself.
    ADD COLUMN decided_at TIMESTAMPTZ,
    ADD COLUMN decided_by_contact_id UUID REFERENCES contacts(id),
    ADD COLUMN decision_notes TEXT,
    -- Set by the phase-4 conversion. UNIQUE below is the real idempotency
    -- guard against a double-click creating two projects.
    ADD COLUMN converted_project_id UUID REFERENCES projects(id);

-- Enforce the client association now that the column exists. Safe because
-- the table is empty (see the safety note above); fails loud rather than
-- silently accepting company-less quotes if that assumption ever breaks.
ALTER TABLE quotes
    ALTER COLUMN company_id SET NOT NULL;

-- ============================================================================
-- 3. Money: reconcile to the DECIMAL(12,2) the rest of the system uses.
-- ============================================================================
-- The stub's `total_cents BIGINT` / `CHAR(3)` is the odd one out: `invoices`,
-- `invoice_lines`, and `projects.budget_amount` all use DECIMAL(12,2) and
-- VARCHAR(3). Reconciling means a quote total, an invoice total, and a
-- project budget compare without unit conversion at every call site.
ALTER TABLE quotes
    ADD COLUMN subtotal DECIMAL(12, 2) NOT NULL DEFAULT 0,
    ADD COLUMN tax_amount DECIMAL(12, 2) NOT NULL DEFAULT 0,
    ADD COLUMN total DECIMAL(12, 2) NOT NULL DEFAULT 0;

-- Backfill from the legacy column. No tax was ever representable in the
-- stub, so the whole amount lands on subtotal and total.
UPDATE quotes
   SET subtotal = total_cents / 100.0,
       total    = total_cents / 100.0
 WHERE total_cents <> 0;

-- CHAR(3) blank-pads on read; VARCHAR(3) matches `invoices.currency`.
ALTER TABLE quotes
    ALTER COLUMN currency TYPE VARCHAR(3);

-- `total_cents` is deliberately NOT dropped. It stays readable while
-- consumers migrate, exactly the posture PMS-470 took with the legacy
-- `ticket_approvals.ticket_id` column: keep it, migrate readers, drop in a
-- later migration once nothing reads it.
COMMENT ON COLUMN quotes.total_cents IS
    'DEPRECATED (PMS-671): superseded by total DECIMAL(12,2). Retained for '
    'backwards-compatible reads; drop once no consumer reads it.';

-- ============================================================================
-- 4. Widen the status CHECK to the full lifecycle.
-- ============================================================================
-- draft -> submitted -> approved -> sent -> accepted -> converted
--                    \-> rejected       \-> declined
--                                       \-> expired
--   (any non-terminal state) -> cancelled
--
-- The four values 078 shipped keep their exact meaning: submitted /
-- approved / rejected are the INTERNAL outcomes driven by the existing
-- approvals surface. `accepted` / `declined` are deliberately different
-- words from `approved` / `rejected` so a reader can always tell a client
-- decision from an internal one.
--
-- Dropped by its Postgres-assigned name (inline column CHECKs are named
-- `<table>_<column>_check`) without IF EXISTS: if that name is ever wrong,
-- the old narrow constraint would survive and silently reject every new
-- status, so failing here is strictly better than succeeding.
ALTER TABLE quotes
    DROP CONSTRAINT quotes_status_check;

ALTER TABLE quotes
    ADD CONSTRAINT quotes_status_check CHECK (status IN (
        'draft',
        'submitted',
        'approved',
        'rejected',
        'sent',
        'accepted',
        'declined',
        'expired',
        'converted',
        'cancelled'
    ));

-- ============================================================================
-- 5. Constraints and indexes.
-- ============================================================================
-- Quote numbers are unique per tenant, matching `invoices`. NULLs are not
-- compared by a UNIQUE constraint in Postgres, so unnumbered stub rows and
-- draft rows awaiting a number do not collide with each other.
ALTER TABLE quotes
    ADD CONSTRAINT quotes_tenant_number_unique UNIQUE (tenant_id, quote_number);

-- A quote converts into at most one project, enforced by the database
-- rather than by an application-level "have we converted yet?" check,
-- which two concurrent requests can both pass.
ALTER TABLE quotes
    ADD CONSTRAINT quotes_converted_project_unique UNIQUE (converted_project_id);

-- "Quotes for this client" (the portal's primary read) and "quotes in this
-- state" (the staff pipeline view) as one index scan each.
CREATE INDEX idx_quotes_tenant_company ON quotes(tenant_id, company_id);
CREATE INDEX idx_quotes_tenant_status ON quotes(tenant_id, status);

-- ============================================================================
-- 6. Line items. Mirrors `invoice_lines` (010_billing).
-- ============================================================================
-- `total` is stored rather than computed so a sent quote keeps the exact
-- figures the client saw, even if a future rounding or tax rule changes.
-- The service layer is what recomputes it; a client-supplied total is
-- never trusted.
CREATE TABLE quote_lines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    quote_id UUID NOT NULL REFERENCES quotes(id) ON DELETE CASCADE,
    line_type VARCHAR(20) NOT NULL DEFAULT 'service'
        CHECK (line_type IN ('service', 'product', 'labour', 'expense', 'adjustment', 'discount')),
    description TEXT NOT NULL,
    quantity DECIMAL(10, 2) NOT NULL DEFAULT 1,
    unit_price DECIMAL(12, 2) NOT NULL,
    total DECIMAL(12, 2) NOT NULL,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_quote_lines_quote ON quote_lines(quote_id);

-- ============================================================================
-- 7. updated_at trigger.
-- ============================================================================
-- 078 created `quotes` after the 024/043 trigger sweeps had already run, so
-- the table has an `updated_at` column that nothing maintains. Attach the
-- standard trigger now that the table is a real, mutable entity.
DROP TRIGGER IF EXISTS update_quotes_updated_at ON quotes;
CREATE TRIGGER update_quotes_updated_at
    BEFORE UPDATE ON quotes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
