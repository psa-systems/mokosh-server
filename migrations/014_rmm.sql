-- PMS-128 split: RMM connections + device mappings + alert rules.

-- ============================================================================
-- RMM INTEGRATION
-- ============================================================================

-- RMM connections
CREATE TABLE rmm_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    provider VARCHAR(30) NOT NULL CHECK (provider IN ('tactical_rmm', 'datto', 'connectwise', 'ninja_rmm')),
    api_url VARCHAR(500) NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    api_secret_encrypted TEXT,
    is_active BOOLEAN DEFAULT FALSE,
    sync_interval_minutes INTEGER DEFAULT 60,
    last_sync_at TIMESTAMPTZ,
    sync_status VARCHAR(20) DEFAULT 'never' CHECK (sync_status IN ('never', 'success', 'failed', 'in_progress')),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rmm_connections_tenant ON rmm_connections(tenant_id);

-- RMM device mappings
CREATE TABLE rmm_device_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rmm_connection_id UUID NOT NULL REFERENCES rmm_connections(id) ON DELETE CASCADE,
    rmm_device_id VARCHAR(255) NOT NULL,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    company_id UUID REFERENCES companies(id),
    device_name VARCHAR(255),
    device_info JSONB DEFAULT '{}',
    last_seen TIMESTAMPTZ,
    sync_status VARCHAR(20) DEFAULT 'pending' CHECK (sync_status IN ('pending', 'synced', 'error')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(rmm_connection_id, rmm_device_id)
);

CREATE INDEX idx_rmm_mappings_connection ON rmm_device_mappings(rmm_connection_id);
CREATE INDEX idx_rmm_mappings_asset ON rmm_device_mappings(asset_id);

-- RMM alert rules
CREATE TABLE rmm_alert_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rmm_connection_id UUID NOT NULL REFERENCES rmm_connections(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    alert_type VARCHAR(100),
    severity_mapping JSONB DEFAULT '{}',
    auto_create_ticket BOOLEAN DEFAULT TRUE,
    ticket_template JSONB DEFAULT '{}',
    assign_to_id UUID REFERENCES users(id),
    queue_id UUID REFERENCES ticket_queues(id),
    is_active BOOLEAN DEFAULT TRUE,
    suppression_rules JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rmm_alert_rules_connection ON rmm_alert_rules(rmm_connection_id);
