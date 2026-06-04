-- PMS-128 split: time tracking (work types, time entries, rounding rules, active timers).

-- ============================================================================
-- TIME TRACKING
-- ============================================================================

-- Work types (billable categories)
CREATE TABLE work_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    default_billable BOOLEAN DEFAULT TRUE,
    default_rate DECIMAL(10, 2),
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_work_types_tenant ON work_types(tenant_id);

-- Time entries
CREATE TABLE time_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    date DATE NOT NULL,
    start_time TIME,
    end_time TIME,
    duration_minutes INTEGER NOT NULL,
    -- Work classification
    work_type_id UUID NOT NULL REFERENCES work_types(id),
    -- Associations
    ticket_id UUID REFERENCES tickets(id),
    project_id UUID,
    task_id UUID,
    company_id UUID NOT NULL REFERENCES companies(id),
    contract_id UUID,
    -- Description
    notes TEXT,
    internal_notes TEXT,
    -- Billing
    is_billable BOOLEAN DEFAULT TRUE,
    billing_status VARCHAR(20) DEFAULT 'not_billed' CHECK (billing_status IN ('not_billed', 'ready_to_bill', 'billed')),
    invoice_id UUID,
    hourly_rate DECIMAL(10, 2),
    total_amount DECIMAL(10, 2),
    -- Approval
    approval_status VARCHAR(20) DEFAULT 'pending' CHECK (approval_status IN ('pending', 'approved', 'rejected')),
    approved_by_id UUID REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    rejection_reason TEXT,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_time_entries_tenant ON time_entries(tenant_id);
CREATE INDEX idx_time_entries_user ON time_entries(user_id);
CREATE INDEX idx_time_entries_date ON time_entries(tenant_id, date);
CREATE INDEX idx_time_entries_ticket ON time_entries(ticket_id);
CREATE INDEX idx_time_entries_project ON time_entries(project_id);
CREATE INDEX idx_time_entries_company ON time_entries(company_id);
CREATE INDEX idx_time_entries_billing ON time_entries(tenant_id, billing_status, is_billable);
CREATE INDEX idx_time_entries_approval ON time_entries(tenant_id, approval_status);

-- Time rounding rules
CREATE TABLE time_rounding_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    increment_minutes INTEGER NOT NULL DEFAULT 15,
    rounding_method VARCHAR(20) NOT NULL DEFAULT 'up' CHECK (rounding_method IN ('up', 'down', 'nearest')),
    minimum_minutes INTEGER DEFAULT 0,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_time_rounding_tenant ON time_rounding_rules(tenant_id);

-- Active timers
CREATE TABLE active_timers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    ticket_id UUID REFERENCES tickets(id),
    project_id UUID,
    task_id UUID,
    company_id UUID REFERENCES companies(id),
    work_type_id UUID REFERENCES work_types(id),
    notes TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Only one active timer per user
    UNIQUE(user_id)
);

CREATE INDEX idx_active_timers_user ON active_timers(user_id);
