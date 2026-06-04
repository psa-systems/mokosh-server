-- PMS-128 split: contracts + items + hour balances + rate cards.

-- ============================================================================
-- CONTRACTS
-- ============================================================================

CREATE TABLE contracts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_number VARCHAR(50),
    name VARCHAR(255) NOT NULL,
    company_id UUID NOT NULL REFERENCES companies(id),
    -- Type
    contract_type VARCHAR(30) NOT NULL CHECK (contract_type IN ('managed_services', 'block_hours', 'time_and_materials', 'fixed_price', 'warranty')),
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'expired', 'cancelled', 'renewed')),
    -- Dates
    start_date DATE NOT NULL,
    end_date DATE,
    -- Renewal
    auto_renew BOOLEAN DEFAULT FALSE,
    renewal_terms JSONB DEFAULT '{}',
    -- Billing
    billing_cycle VARCHAR(20) DEFAULT 'monthly' CHECK (billing_cycle IN ('monthly', 'quarterly', 'annually', 'one_time')),
    billing_amount DECIMAL(12, 2),
    -- SLA
    sla_id UUID,
    -- Signing
    signed_date DATE,
    signed_by_contact_id UUID REFERENCES contacts(id),
    -- Notes
    notes TEXT,
    internal_notes TEXT,
    -- Metadata
    custom_fields JSONB NOT NULL DEFAULT '{}',
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contracts_tenant ON contracts(tenant_id);
CREATE INDEX idx_contracts_company ON contracts(company_id);
CREATE INDEX idx_contracts_status ON contracts(tenant_id, status);
CREATE INDEX idx_contracts_dates ON contracts(start_date, end_date);

-- Contract items/services
CREATE TABLE contract_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_id UUID NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    item_type VARCHAR(30) NOT NULL CHECK (item_type IN ('recurring_service', 'block_hours', 'retainer', 'product', 'one_time')),
    quantity DECIMAL(10, 2) DEFAULT 1,
    unit_price DECIMAL(12, 2) NOT NULL,
    total_price DECIMAL(12, 2) NOT NULL,
    billing_frequency VARCHAR(20) DEFAULT 'monthly',
    work_type_id UUID REFERENCES work_types(id),
    -- For block hour items
    included_hours DECIMAL(10, 2),
    overage_rate DECIMAL(10, 2),
    rollover_enabled BOOLEAN DEFAULT FALSE,
    max_rollover_hours DECIMAL(10, 2),
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contract_items_contract ON contract_items(contract_id);

-- Contract hour balances (for block hour tracking)
CREATE TABLE contract_hour_balances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_id UUID NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    contract_item_id UUID NOT NULL REFERENCES contract_items(id) ON DELETE CASCADE,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    hours_included DECIMAL(10, 2) NOT NULL,
    hours_used DECIMAL(10, 2) DEFAULT 0,
    hours_remaining DECIMAL(10, 2) NOT NULL,
    rollover_hours DECIMAL(10, 2) DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_hour_balances_contract ON contract_hour_balances(contract_id);
CREATE INDEX idx_hour_balances_period ON contract_hour_balances(period_start, period_end);

-- Rate cards
CREATE TABLE rate_cards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rate_cards_tenant ON rate_cards(tenant_id);

CREATE TABLE rate_card_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rate_card_id UUID NOT NULL REFERENCES rate_cards(id) ON DELETE CASCADE,
    work_type_id UUID NOT NULL REFERENCES work_types(id),
    hourly_rate DECIMAL(10, 2) NOT NULL,
    after_hours_rate DECIMAL(10, 2),
    emergency_rate DECIMAL(10, 2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(rate_card_id, work_type_id)
);

CREATE INDEX idx_rate_card_items_card ON rate_card_items(rate_card_id);
