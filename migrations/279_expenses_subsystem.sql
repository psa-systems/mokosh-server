-- MAPPS-1100 scaffold: the BillsAndExpenses subsystem's schema.
--
-- An MSP's own bills (vendor subscriptions, hardware, hosting, contractor
-- invoices received) and expenses (travel, equipment, reimbursables) are a
-- tenant-level accounting plane adjacent to the customer-facing invoicing
-- plane (`invoices` / `invoice_lines`). The customer-facing plane exists
-- end-to-end today; this schema is the inbound plane the Capability::BillsAndExpenses
-- registry entry promises but could not deliver (fork survey: zero
-- expense/bill/payable modules in src/).
--
-- Shipped as its own migration ahead of the Rust side so the schema is
-- settled before the first service.rs method writes to it. The Rust
-- models that mirror this schema land beside it in
-- `src/modules/expenses/models.rs`; the routes + service + worker are
-- deferred to later phases of MAPPS-1100 (see the module doc comment).
--
-- Six tables. All tenant-scoped with the fail-closed `tenant_isolation`
-- RLS policy mirroring 038_rls_fail_closed.sql / 094 / 095 (an unset or
-- empty `app.current_tenant` GUC collapses to NULL, so USING matches no
-- rows and WITH CHECK rejects writes; FORCE binds the owner too), and
-- all granted to `mokosh_app` (PMS-1265) so the serving role can touch
-- them once Phase A's service lands.
--
-- Serving code path: there is NO service code in Phase 0, so no serving
-- query reaches these tables yet. Phase A's `expenses::service` must run
-- every query through `Database::begin_with_tenant` (PMS-285 posture),
-- same as every other RLS-protected table.

-- Vendors the MSP buys from. Separate from `companies` (the MSP's own
-- customers): a vendor can be a customer too, but the roles are different
-- and conflating them would mix two ledgers.
CREATE TABLE IF NOT EXISTS vendors (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name text NOT NULL,
    account_number text,
    default_currency text,
    notes text,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS vendors_tenant_id_idx ON vendors (tenant_id);
CREATE INDEX IF NOT EXISTS vendors_tenant_name_idx ON vendors (tenant_id, lower(name));
ALTER TABLE vendors ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON vendors
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON vendors TO mokosh_app;

-- Categories to classify what a bill or an expense was for. One shared
-- taxonomy per tenant; a tenant seeds its own set rather than inheriting
-- a global list.
CREATE TABLE IF NOT EXISTS expense_categories (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name text NOT NULL,
    is_active boolean NOT NULL DEFAULT TRUE,
    created_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS expense_categories_tenant_id_idx ON expense_categories (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS expense_categories_tenant_name_uq
    ON expense_categories (tenant_id, lower(name));
ALTER TABLE expense_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE expense_categories FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON expense_categories
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON expense_categories TO mokosh_app;

-- A bill from a vendor: what the MSP owes, with a due date and a status
-- (draft, approved, paid, void). Lines break down the bill.
CREATE TABLE IF NOT EXISTS bills (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
    bill_number text,
    issue_date date NOT NULL,
    due_date date,
    currency text NOT NULL,
    subtotal_minor bigint NOT NULL DEFAULT 0,
    tax_minor bigint NOT NULL DEFAULT 0,
    total_minor bigint NOT NULL DEFAULT 0,
    paid_minor bigint NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'approved', 'paid', 'void')),
    notes text,
    -- MAPPS-1099 posture mirrored here for the delegation phase of
    -- MAPPS-1100: when a tenant delegates BillsAndExpenses to Xero or
    -- QuickBooks, the external provider is the system of record for the
    -- bill. NULLs mean a Mokosh-held bill.
    external_provider text,
    external_bill_id text,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS bills_tenant_id_idx ON bills (tenant_id);
CREATE INDEX IF NOT EXISTS bills_tenant_vendor_idx ON bills (tenant_id, vendor_id);
CREATE INDEX IF NOT EXISTS bills_tenant_status_due_idx ON bills (tenant_id, status, due_date);
ALTER TABLE bills ENABLE ROW LEVEL SECURITY;
ALTER TABLE bills FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bills
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON bills TO mokosh_app;

CREATE TABLE IF NOT EXISTS bill_lines (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bill_id uuid NOT NULL REFERENCES bills(id) ON DELETE CASCADE,
    category_id uuid REFERENCES expense_categories(id) ON DELETE SET NULL,
    description text NOT NULL,
    quantity_hundredths bigint NOT NULL DEFAULT 100,
    unit_price_minor bigint NOT NULL,
    tax_minor bigint NOT NULL DEFAULT 0,
    total_minor bigint NOT NULL,
    position integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS bill_lines_tenant_id_idx ON bill_lines (tenant_id);
CREATE INDEX IF NOT EXISTS bill_lines_bill_id_idx ON bill_lines (bill_id);
ALTER TABLE bill_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE bill_lines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bill_lines
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON bill_lines TO mokosh_app;

-- An expense: what one of the MSP's own people spent, pending approval
-- and reimbursement. Lines break down the receipt.
CREATE TABLE IF NOT EXISTS expenses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    incurred_on date NOT NULL,
    currency text NOT NULL,
    subtotal_minor bigint NOT NULL DEFAULT 0,
    tax_minor bigint NOT NULL DEFAULT 0,
    total_minor bigint NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'submitted', 'approved', 'reimbursed', 'rejected')),
    approver_id uuid REFERENCES users(id) ON DELETE SET NULL,
    approved_at timestamptz,
    reimbursed_at timestamptz,
    notes text,
    external_provider text,
    external_expense_id text,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS expenses_tenant_id_idx ON expenses (tenant_id);
CREATE INDEX IF NOT EXISTS expenses_tenant_user_idx ON expenses (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS expenses_tenant_status_idx ON expenses (tenant_id, status);
ALTER TABLE expenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE expenses FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON expenses
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON expenses TO mokosh_app;

CREATE TABLE IF NOT EXISTS expense_lines (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    expense_id uuid NOT NULL REFERENCES expenses(id) ON DELETE CASCADE,
    category_id uuid REFERENCES expense_categories(id) ON DELETE SET NULL,
    description text NOT NULL,
    amount_minor bigint NOT NULL,
    tax_minor bigint NOT NULL DEFAULT 0,
    position integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS expense_lines_tenant_id_idx ON expense_lines (tenant_id);
CREATE INDEX IF NOT EXISTS expense_lines_expense_id_idx ON expense_lines (expense_id);
ALTER TABLE expense_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE expense_lines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON expense_lines
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON expense_lines TO mokosh_app;
