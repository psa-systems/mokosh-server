-- PMS-315: mileage entries (Log Time "Mileage" mode) + rate-card per-mile rate
-- + invoice line type 'mileage'.
--
-- Field-service techs log billable transportation as a first-class entry that
-- mirrors `time_entries` (006_time_tracking.sql) in FK shape and billing /
-- approval lifecycle, but swaps the hours axis for a distance axis. A separate
-- table (rather than widening time_entries with NULL mileage columns + an
-- entry_kind discriminator) keeps both query paths simple; invoicing pulls from
-- BOTH tables when building line items.

-- ============================================================================
-- RATE CARDS: per-mile default rate
-- ============================================================================

-- The tenant's default rate card is the canonical home for a default per-mile
-- reimbursement rate. A mileage entry with no explicit `rate_per_mile` inherits
-- this, mirroring how a time entry inherits a work type's `default_rate`.
ALTER TABLE rate_cards
    ADD COLUMN default_per_mile_rate DECIMAL(8, 4);

-- ============================================================================
-- MILEAGE ENTRIES
-- ============================================================================

CREATE TABLE mileage_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    date DATE NOT NULL,
    -- Distance axis (replaces time_entries' duration_minutes).
    distance_miles NUMERIC(8, 2) NOT NULL CHECK (distance_miles > 0),
    start_address TEXT,
    end_address TEXT,
    -- Associations: same shape as time_entries so a mileage entry can hang off
    -- the same job as the matching hours entry.
    ticket_id UUID REFERENCES tickets(id),
    project_id UUID,
    task_id UUID,
    company_id UUID NOT NULL REFERENCES companies(id),
    contract_id UUID,
    -- Description
    notes TEXT,
    -- Billing. `rate_per_mile` NULL means "inherit the default rate card rate";
    -- `total_amount` is distance_miles * rate_per_mile, computed at write time
    -- for a billable entry (mirrors time_entries.total_amount).
    is_billable BOOLEAN NOT NULL DEFAULT TRUE,
    rate_per_mile NUMERIC(8, 4),
    total_amount NUMERIC(10, 2),
    billing_status VARCHAR(20) DEFAULT 'not_billed' CHECK (billing_status IN ('not_billed', 'ready_to_bill', 'billed')),
    invoice_id UUID,
    -- Approval (enum mirrors time_entries; no approval workflow ships here).
    approval_status VARCHAR(20) DEFAULT 'pending' CHECK (approval_status IN ('draft', 'pending', 'approved', 'rejected')),
    approved_by_id UUID REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    rejection_reason TEXT,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mileage_entries_tenant ON mileage_entries(tenant_id);
CREATE INDEX idx_mileage_entries_user ON mileage_entries(user_id);
CREATE INDEX idx_mileage_entries_date ON mileage_entries(tenant_id, date);
CREATE INDEX idx_mileage_entries_ticket ON mileage_entries(ticket_id);
CREATE INDEX idx_mileage_entries_project ON mileage_entries(project_id);
CREATE INDEX idx_mileage_entries_company ON mileage_entries(company_id);
CREATE INDEX idx_mileage_entries_billing ON mileage_entries(tenant_id, billing_status, is_billable);
CREATE INDEX idx_mileage_entries_approval ON mileage_entries(tenant_id, approval_status);

-- updated_at trigger. 024's trigger loop already ran, so a table created now
-- does NOT inherit it; attach explicitly (mirrors 048's lookup tables).
CREATE TRIGGER update_mileage_entries_updated_at
    BEFORE UPDATE ON mileage_entries
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Row-level security. The fail-closed `tenant_isolation` policy is attached by
-- a DO-block loop over `information_schema` in 024/038, but those loops already
-- ran, so a table created now does NOT inherit the policy. Attach the same
-- fail-closed, FORCE'd policy explicitly (PMS-257 posture) so mileage_entries
-- is tenant-isolated the moment the application drops its BYPASSRLS role. The
-- GUC is set transaction-locally by `Database::begin_with_tenant`.
ALTER TABLE mileage_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mileage_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mileage_entries
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- ============================================================================
-- INVOICE LINE TYPE: 'mileage'
-- ============================================================================

-- Invoice builder picks up unbilled mileage entries alongside time entries.
-- Widen the inline CHECK (010_billing.sql) to admit the new line type. The
-- inline constraint is auto-named `invoice_lines_line_type_check`.
ALTER TABLE invoice_lines
    DROP CONSTRAINT IF EXISTS invoice_lines_line_type_check;
ALTER TABLE invoice_lines
    ADD CONSTRAINT invoice_lines_line_type_check
    CHECK (line_type IN ('service', 'product', 'time_entry', 'mileage', 'adjustment', 'tax', 'discount'));
