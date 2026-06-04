-- PMS-128 split: assets + asset relationships + configuration items + credential vault + asset audit log.

-- ============================================================================
-- ASSET MANAGEMENT (CMDB)
-- ============================================================================

-- Asset types
CREATE TABLE asset_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    icon VARCHAR(50),
    parent_type_id UUID REFERENCES asset_types(id),
    custom_fields_schema JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_asset_types_tenant ON asset_types(tenant_id);

-- Assets
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_tag VARCHAR(100),
    name VARCHAR(255) NOT NULL,
    asset_type_id UUID NOT NULL REFERENCES asset_types(id),
    -- Associations
    company_id UUID NOT NULL REFERENCES companies(id),
    site_id UUID REFERENCES sites(id),
    contact_id UUID REFERENCES contacts(id),
    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'retired', 'in_repair', 'in_stock')),
    -- Details
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(100),
    -- Dates
    purchase_date DATE,
    purchase_price DECIMAL(12, 2),
    warranty_expiry DATE,
    end_of_life DATE,
    -- RMM integration
    rmm_device_id VARCHAR(255),
    last_sync_at TIMESTAMPTZ,
    -- Metadata
    custom_fields JSONB NOT NULL DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    notes TEXT,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_assets_tenant ON assets(tenant_id);
CREATE INDEX idx_assets_company ON assets(company_id);
CREATE INDEX idx_assets_site ON assets(site_id);
CREATE INDEX idx_assets_type ON assets(asset_type_id);
CREATE INDEX idx_assets_status ON assets(tenant_id, status);
CREATE INDEX idx_assets_rmm ON assets(rmm_device_id) WHERE rmm_device_id IS NOT NULL;
CREATE INDEX idx_assets_serial ON assets(tenant_id, serial_number);
CREATE INDEX idx_assets_name_trgm ON assets USING gin (name gin_trgm_ops);

-- Asset relationships
CREATE TABLE asset_relationships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    parent_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    child_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    relationship_type VARCHAR(20) NOT NULL CHECK (relationship_type IN ('contains', 'connected_to', 'depends_on', 'hosts')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(parent_asset_id, child_asset_id, relationship_type)
);

CREATE INDEX idx_asset_relationships_parent ON asset_relationships(parent_asset_id);
CREATE INDEX idx_asset_relationships_child ON asset_relationships(child_asset_id);

-- Configuration items (for storing config data on assets)
CREATE TABLE configuration_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(100),
    value_encrypted TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_config_items_asset ON configuration_items(asset_id);

-- Credential vault
CREATE TABLE credential_vault (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    company_id UUID REFERENCES companies(id),
    asset_id UUID REFERENCES assets(id),
    credential_type VARCHAR(20) NOT NULL CHECK (credential_type IN ('local_admin', 'domain', 'ssh', 'api', 'other')),
    username_encrypted TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    url VARCHAR(500),
    notes_encrypted TEXT,
    last_rotated TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credential_vault_tenant ON credential_vault(tenant_id);
CREATE INDEX idx_credential_vault_company ON credential_vault(company_id);
CREATE INDEX idx_credential_vault_asset ON credential_vault(asset_id);

-- Asset audit log
CREATE TABLE asset_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    action VARCHAR(20) NOT NULL CHECK (action IN ('created', 'updated', 'synced', 'status_changed')),
    changes JSONB,
    performed_by_id UUID REFERENCES users(id),
    performed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_asset_audit_asset ON asset_audit_log(asset_id);
CREATE INDEX idx_asset_audit_date ON asset_audit_log(performed_at);
