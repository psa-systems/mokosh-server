-- PMS-128 split: invoices + invoice lines + payments + payment-gateway configs + tax rates.

-- ============================================================================
-- BILLING & INVOICING
-- ============================================================================

CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    invoice_number VARCHAR(50) NOT NULL,
    company_id UUID NOT NULL REFERENCES companies(id),
    billing_contact_id UUID REFERENCES contacts(id),
    contract_id UUID REFERENCES contracts(id),
    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'pending', 'sent', 'paid', 'partially_paid', 'void', 'written_off')),
    -- Dates
    invoice_date DATE NOT NULL,
    due_date DATE NOT NULL,
    -- Terms
    payment_terms VARCHAR(20) DEFAULT 'net30',
    -- Amounts
    subtotal DECIMAL(12, 2) NOT NULL DEFAULT 0,
    tax_amount DECIMAL(12, 2) NOT NULL DEFAULT 0,
    discount_amount DECIMAL(12, 2) NOT NULL DEFAULT 0,
    total DECIMAL(12, 2) NOT NULL DEFAULT 0,
    amount_paid DECIMAL(12, 2) NOT NULL DEFAULT 0,
    balance_due DECIMAL(12, 2) NOT NULL DEFAULT 0,
    -- Currency
    currency VARCHAR(3) DEFAULT 'USD',
    -- Notes
    notes TEXT,
    internal_notes TEXT,
    -- PO reference
    po_number VARCHAR(100),
    -- Email tracking
    sent_at TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, invoice_number)
);

CREATE INDEX idx_invoices_tenant ON invoices(tenant_id);
CREATE INDEX idx_invoices_company ON invoices(company_id);
CREATE INDEX idx_invoices_status ON invoices(tenant_id, status);
CREATE INDEX idx_invoices_date ON invoices(invoice_date);
CREATE INDEX idx_invoices_due ON invoices(due_date) WHERE status NOT IN ('paid', 'void');

-- Invoice sequence
CREATE TABLE invoice_sequences (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    last_number INTEGER NOT NULL DEFAULT 0,
    prefix VARCHAR(10) DEFAULT 'INV-'
);

-- Invoice lines
CREATE TABLE invoice_lines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    line_type VARCHAR(20) NOT NULL DEFAULT 'service' CHECK (line_type IN ('service', 'product', 'time_entry', 'adjustment', 'tax', 'discount')),
    description TEXT NOT NULL,
    quantity DECIMAL(10, 2) NOT NULL DEFAULT 1,
    unit_price DECIMAL(12, 2) NOT NULL,
    total DECIMAL(12, 2) NOT NULL,
    -- References
    time_entry_ids UUID[],
    ticket_id UUID REFERENCES tickets(id),
    project_id UUID REFERENCES projects(id),
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invoice_lines_invoice ON invoice_lines(invoice_id);

-- Payments
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    invoice_id UUID REFERENCES invoices(id),
    company_id UUID NOT NULL REFERENCES companies(id),
    payment_date DATE NOT NULL,
    amount DECIMAL(12, 2) NOT NULL,
    payment_method VARCHAR(20) NOT NULL CHECK (payment_method IN ('check', 'credit_card', 'ach', 'wire', 'cash', 'other')),
    reference_number VARCHAR(100),
    -- Gateway info
    gateway_transaction_id VARCHAR(255),
    gateway_response JSONB,
    -- Notes
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_payments_tenant ON payments(tenant_id);
CREATE INDEX idx_payments_invoice ON payments(invoice_id);
CREATE INDEX idx_payments_company ON payments(company_id);
CREATE INDEX idx_payments_date ON payments(payment_date);

-- Payment gateway configuration
CREATE TABLE payment_gateway_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL CHECK (provider IN ('stripe', 'authorize_net', 'paypal')),
    is_active BOOLEAN DEFAULT FALSE,
    is_test_mode BOOLEAN DEFAULT TRUE,
    config_encrypted TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, provider)
);

CREATE INDEX idx_payment_gateway_tenant ON payment_gateway_configs(tenant_id);

-- Tax rates
CREATE TABLE tax_rates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    rate DECIMAL(5, 4) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tax_rates_tenant ON tax_rates(tenant_id);
