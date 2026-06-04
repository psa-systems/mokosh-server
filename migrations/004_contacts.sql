-- PMS-128 split: companies + contacts + sites.

-- ============================================================================
-- COMPANIES (Clients)
-- ============================================================================

CREATE TABLE companies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    parent_company_id UUID REFERENCES companies(id),
    company_type VARCHAR(20) NOT NULL DEFAULT 'client' CHECK (company_type IN ('client', 'prospect', 'vendor', 'partner')),
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'prospect')),
    industry VARCHAR(100),
    website VARCHAR(255),
    phone VARCHAR(50),
    fax VARCHAR(50),
    -- Address
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100) DEFAULT 'USA',
    -- Billing address (if different)
    billing_address_line1 VARCHAR(255),
    billing_address_line2 VARCHAR(255),
    billing_city VARCHAR(100),
    billing_state VARCHAR(100),
    billing_postal_code VARCHAR(20),
    billing_country VARCHAR(100),
    -- References
    tax_id VARCHAR(50),
    account_number VARCHAR(50),
    default_billing_contact_id UUID,
    default_technical_contact_id UUID,
    account_manager_id UUID REFERENCES users(id),
    -- Settings
    sla_id UUID,
    default_contract_id UUID,
    payment_terms VARCHAR(20) DEFAULT 'net30',
    tax_exempt BOOLEAN DEFAULT FALSE,
    -- Metadata
    custom_fields JSONB NOT NULL DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    notes TEXT,
    logo_url VARCHAR(500),
    -- Portal settings
    portal_enabled BOOLEAN DEFAULT TRUE,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_companies_tenant ON companies(tenant_id);
CREATE INDEX idx_companies_name ON companies(tenant_id, name);
CREATE INDEX idx_companies_type ON companies(tenant_id, company_type);
CREATE INDEX idx_companies_status ON companies(tenant_id, status);
CREATE INDEX idx_companies_parent ON companies(parent_company_id);
CREATE INDEX idx_companies_account_manager ON companies(account_manager_id);
CREATE INDEX idx_companies_name_trgm ON companies USING gin (name gin_trgm_ops);

-- ============================================================================
-- CONTACTS
-- ============================================================================

CREATE TABLE contacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    mobile VARCHAR(50),
    fax VARCHAR(50),
    title VARCHAR(100),
    department VARCHAR(100),
    contact_type VARCHAR(20) NOT NULL DEFAULT 'other' CHECK (contact_type IN ('primary', 'technical', 'billing', 'other')),
    -- Portal access
    is_portal_user BOOLEAN DEFAULT FALSE,
    portal_user_id UUID,
    portal_password_hash VARCHAR(255),
    portal_last_login_at TIMESTAMPTZ,
    -- Preferences
    preferred_contact_method VARCHAR(20) DEFAULT 'email' CHECK (preferred_contact_method IN ('email', 'phone', 'mobile')),
    timezone VARCHAR(50) DEFAULT 'UTC',
    locale VARCHAR(10) DEFAULT 'en-US',
    -- Metadata
    custom_fields JSONB NOT NULL DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    notes TEXT,
    avatar_url VARCHAR(500),
    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contacts_tenant ON contacts(tenant_id);
CREATE INDEX idx_contacts_company ON contacts(company_id);
CREATE INDEX idx_contacts_email ON contacts(tenant_id, email);
CREATE INDEX idx_contacts_type ON contacts(company_id, contact_type);
CREATE INDEX idx_contacts_portal ON contacts(tenant_id, is_portal_user) WHERE is_portal_user = TRUE;
CREATE INDEX idx_contacts_name_trgm ON contacts USING gin ((first_name || ' ' || last_name) gin_trgm_ops);

-- ============================================================================
-- SITES (Company Locations)
-- ============================================================================

CREATE TABLE sites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100) DEFAULT 'USA',
    phone VARCHAR(50),
    is_primary BOOLEAN DEFAULT FALSE,
    timezone VARCHAR(50) DEFAULT 'UTC',
    notes TEXT,
    -- Geolocation for dispatch
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sites_tenant ON sites(tenant_id);
CREATE INDEX idx_sites_company ON sites(company_id);
