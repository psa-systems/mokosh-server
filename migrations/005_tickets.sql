-- PMS-128 split: ticket configuration + tickets + automation + email integration + SLA.
-- SLA targets reference ticket_priorities, so the SLA tables live in the same file as tickets.

-- ============================================================================
-- TICKET CONFIGURATION
-- ============================================================================

-- Ticket queues/boards
CREATE TABLE ticket_queues (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    color VARCHAR(7),
    icon VARCHAR(50),
    is_default BOOLEAN DEFAULT FALSE,
    sort_order INTEGER DEFAULT 0,
    -- Access control
    visible_to_roles TEXT[] DEFAULT '{}',
    assignable_to_team_id UUID REFERENCES teams(id),
    -- Automation
    default_sla_id UUID,
    auto_assign_rules JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ticket_queues_tenant ON ticket_queues(tenant_id);

-- Ticket statuses
CREATE TABLE ticket_statuses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    color VARCHAR(7) NOT NULL,
    is_closed BOOLEAN DEFAULT FALSE,
    is_default BOOLEAN DEFAULT FALSE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ticket_statuses_tenant ON ticket_statuses(tenant_id);

-- Ticket priorities
CREATE TABLE ticket_priorities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    color VARCHAR(7) NOT NULL,
    icon VARCHAR(50),
    sla_multiplier DECIMAL(3, 2) DEFAULT 1.00,
    sort_order INTEGER DEFAULT 0,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ticket_priorities_tenant ON ticket_priorities(tenant_id);

-- Ticket types
CREATE TABLE ticket_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ticket_types_tenant ON ticket_types(tenant_id);

-- Ticket categories
CREATE TABLE ticket_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES ticket_categories(id),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ticket_categories_tenant ON ticket_categories(tenant_id);
CREATE INDEX idx_ticket_categories_parent ON ticket_categories(parent_id);

-- ============================================================================
-- TICKETS
-- ============================================================================

CREATE TABLE tickets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ticket_number VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    -- Classification
    status_id UUID NOT NULL REFERENCES ticket_statuses(id),
    priority_id UUID NOT NULL REFERENCES ticket_priorities(id),
    type_id UUID REFERENCES ticket_types(id),
    category_id UUID REFERENCES ticket_categories(id),
    subcategory_id UUID REFERENCES ticket_categories(id),
    queue_id UUID NOT NULL REFERENCES ticket_queues(id),
    -- Source
    source VARCHAR(20) NOT NULL DEFAULT 'portal' CHECK (source IN ('portal', 'email', 'phone', 'api', 'chat', 'rmm', 'internal')),
    -- Relationships
    company_id UUID NOT NULL REFERENCES companies(id),
    contact_id UUID REFERENCES contacts(id),
    site_id UUID REFERENCES sites(id),
    -- Assignment
    assigned_to_id UUID REFERENCES users(id),
    team_id UUID REFERENCES teams(id),
    -- Parent ticket (for sub-tickets)
    parent_ticket_id UUID REFERENCES tickets(id),
    -- Contracts and SLA
    contract_id UUID,
    sla_id UUID,
    -- SLA tracking
    sla_due_date TIMESTAMPTZ,
    first_response_due TIMESTAMPTZ,
    first_response_at TIMESTAMPTZ,
    resolution_due TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    -- Scheduling
    scheduled_start TIMESTAMPTZ,
    scheduled_end TIMESTAMPTZ,
    -- Time tracking
    estimated_hours DECIMAL(10, 2),
    actual_hours DECIMAL(10, 2) DEFAULT 0,
    -- Billing
    is_billable BOOLEAN DEFAULT TRUE,
    billing_status VARCHAR(20) DEFAULT 'not_billed' CHECK (billing_status IN ('not_billed', 'ready_to_bill', 'billed')),
    -- Linked asset
    asset_id UUID,
    -- Email tracking
    email_message_id VARCHAR(255),
    email_thread_id VARCHAR(255),
    -- Metadata
    custom_fields JSONB NOT NULL DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    -- Audit
    created_by_id UUID NOT NULL REFERENCES users(id),
    last_updated_by_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Unique ticket number per tenant
    UNIQUE(tenant_id, ticket_number)
);

CREATE INDEX idx_tickets_tenant ON tickets(tenant_id);
CREATE INDEX idx_tickets_number ON tickets(tenant_id, ticket_number);
CREATE INDEX idx_tickets_status ON tickets(tenant_id, status_id);
CREATE INDEX idx_tickets_priority ON tickets(tenant_id, priority_id);
CREATE INDEX idx_tickets_queue ON tickets(queue_id);
CREATE INDEX idx_tickets_company ON tickets(company_id);
CREATE INDEX idx_tickets_contact ON tickets(contact_id);
CREATE INDEX idx_tickets_assigned ON tickets(assigned_to_id);
CREATE INDEX idx_tickets_team ON tickets(team_id);
CREATE INDEX idx_tickets_parent ON tickets(parent_ticket_id);
CREATE INDEX idx_tickets_sla_due ON tickets(tenant_id, sla_due_date) WHERE closed_at IS NULL;
CREATE INDEX idx_tickets_created ON tickets(tenant_id, created_at);
CREATE INDEX idx_tickets_title_trgm ON tickets USING gin (title gin_trgm_ops);

-- Ticket sequence for auto-incrementing ticket numbers
CREATE TABLE ticket_sequences (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    last_number INTEGER NOT NULL DEFAULT 0
);

-- Ticket notes
CREATE TABLE ticket_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    note_type VARCHAR(20) NOT NULL DEFAULT 'internal' CHECK (note_type IN ('internal', 'public', 'resolution', 'time_entry')),
    content TEXT NOT NULL,
    content_html TEXT,
    -- Email tracking
    is_email_sent BOOLEAN DEFAULT FALSE,
    email_sent_at TIMESTAMPTZ,
    email_recipients TEXT[],
    -- Audit
    created_by_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ticket_notes_ticket ON ticket_notes(ticket_id);
CREATE INDEX idx_ticket_notes_type ON ticket_notes(ticket_id, note_type);
CREATE INDEX idx_ticket_notes_created ON ticket_notes(created_at);

-- Ticket attachments
CREATE TABLE ticket_attachments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    note_id UUID REFERENCES ticket_notes(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    storage_path VARCHAR(500) NOT NULL,
    uploaded_by_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ticket_attachments_ticket ON ticket_attachments(ticket_id);
CREATE INDEX idx_ticket_attachments_note ON ticket_attachments(note_id);

-- ============================================================================
-- TICKET AUTOMATION
-- ============================================================================

CREATE TABLE ticket_automation_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    trigger_type VARCHAR(30) NOT NULL CHECK (trigger_type IN ('on_create', 'on_update', 'on_schedule', 'on_sla_breach', 'on_sla_warning', 'on_aging')),
    -- Conditions (JSON structure defining when rule applies)
    conditions JSONB NOT NULL DEFAULT '[]',
    -- Actions (JSON structure defining what to do)
    actions JSONB NOT NULL DEFAULT '[]',
    -- Execution order
    priority INTEGER DEFAULT 100,
    -- Stats
    last_run_at TIMESTAMPTZ,
    run_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_automation_rules_tenant ON ticket_automation_rules(tenant_id);
CREATE INDEX idx_automation_rules_trigger ON ticket_automation_rules(tenant_id, trigger_type, is_active);

-- ============================================================================
-- EMAIL INTEGRATION
-- ============================================================================

CREATE TABLE email_mailboxes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    email_address VARCHAR(255) NOT NULL,
    -- Connection settings (encrypted)
    imap_host VARCHAR(255),
    imap_port INTEGER DEFAULT 993,
    imap_username VARCHAR(255),
    imap_password_encrypted TEXT,
    smtp_host VARCHAR(255),
    smtp_port INTEGER DEFAULT 587,
    smtp_username VARCHAR(255),
    smtp_password_encrypted TEXT,
    -- Processing
    is_active BOOLEAN DEFAULT TRUE,
    last_checked_at TIMESTAMPTZ,
    last_error TEXT,
    -- Default settings for new tickets
    default_queue_id UUID REFERENCES ticket_queues(id),
    default_type_id UUID REFERENCES ticket_types(id),
    default_priority_id UUID REFERENCES ticket_priorities(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_mailboxes_tenant ON email_mailboxes(tenant_id);
CREATE INDEX idx_email_mailboxes_active ON email_mailboxes(is_active);

CREATE TABLE email_parse_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    mailbox_id UUID NOT NULL REFERENCES email_mailboxes(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,
    -- Matching conditions
    conditions JSONB NOT NULL DEFAULT '{}',
    -- Actions when matched
    actions JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_parse_rules_mailbox ON email_parse_rules(mailbox_id);


-- ============================================================================
-- SLA MANAGEMENT
-- ============================================================================

-- Business hours definitions
CREATE TABLE business_hours (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    schedule JSONB NOT NULL DEFAULT '{}',
    holidays UUID[],
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_business_hours_tenant ON business_hours(tenant_id);

-- Holiday calendars
CREATE TABLE holiday_calendars (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    holidays JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_holiday_calendars_tenant ON holiday_calendars(tenant_id);

-- SLA policies
CREATE TABLE sla_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    business_hours_id UUID REFERENCES business_hours(id),
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sla_policies_tenant ON sla_policies(tenant_id);

-- SLA targets (per priority)
CREATE TABLE sla_targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sla_policy_id UUID NOT NULL REFERENCES sla_policies(id) ON DELETE CASCADE,
    priority_id UUID NOT NULL REFERENCES ticket_priorities(id),
    first_response_hours DECIMAL(10, 2),
    resolution_hours DECIMAL(10, 2),
    operational_hours VARCHAR(20) DEFAULT 'business_hours' CHECK (operational_hours IN ('business_hours', '24x7')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(sla_policy_id, priority_id)
);

CREATE INDEX idx_sla_targets_policy ON sla_targets(sla_policy_id);
