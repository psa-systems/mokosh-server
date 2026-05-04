-- Mokosh Server Initial Schema
-- This migration creates the core tables for Mokosh Server

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For fuzzy text search

-- ============================================================================
-- TENANTS (Multi-tenant support)
-- ============================================================================

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled')),
    settings JSONB NOT NULL DEFAULT '{}',
    branding JSONB NOT NULL DEFAULT '{}',
    billing_email VARCHAR(255),
    billing_contact_name VARCHAR(255),
    subscription_plan VARCHAR(50),
    subscription_status VARCHAR(20) DEFAULT 'trialing',
    trial_ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);

-- ============================================================================
-- USERS & AUTHENTICATION
-- ============================================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone VARCHAR(50),
    mobile VARCHAR(50),
    title VARCHAR(100),
    avatar_url VARCHAR(500),
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    locale VARCHAR(10) NOT NULL DEFAULT 'en-US',
    role VARCHAR(50) NOT NULL DEFAULT 'technician' CHECK (role IN ('super_admin', 'admin', 'manager', 'technician', 'dispatcher', 'sales', 'finance')),
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'pending')),
    email_verified_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(100),
    notification_preferences JSONB NOT NULL DEFAULT '{}',
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(tenant_id, role);
CREATE INDEX idx_users_status ON users(tenant_id, status);

-- User sessions
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_sessions_token ON user_sessions(token_hash);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);

-- API keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_prefix VARCHAR(10) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '["*"]',
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_reset_token ON password_reset_tokens(token_hash);

-- ============================================================================
-- TEAMS
-- ============================================================================

CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    manager_id UUID REFERENCES users(id),
    color VARCHAR(7),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_teams_tenant ON teams(tenant_id);

CREATE TABLE team_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL DEFAULT 'member' CHECK (role IN ('leader', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(team_id, user_id)
);

CREATE INDEX idx_team_members_team ON team_members(team_id);
CREATE INDEX idx_team_members_user ON team_members(user_id);

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

-- ============================================================================
-- PROJECTS & TASKS
-- ============================================================================

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    project_number VARCHAR(50),
    -- Associations
    company_id UUID REFERENCES companies(id),
    contract_id UUID,
    -- Classification
    project_type VARCHAR(20) NOT NULL DEFAULT 'client' CHECK (project_type IN ('client', 'internal')),
    status VARCHAR(20) NOT NULL DEFAULT 'planning' CHECK (status IN ('planning', 'active', 'on_hold', 'completed', 'cancelled')),
    -- Management
    project_manager_id UUID REFERENCES users(id),
    -- Dates
    start_date DATE,
    target_end_date DATE,
    actual_end_date DATE,
    -- Budget
    budget_hours DECIMAL(10, 2),
    budget_amount DECIMAL(12, 2),
    -- Billing
    billing_method VARCHAR(20) DEFAULT 'time_and_materials' CHECK (billing_method IN ('fixed_price', 'time_and_materials', 'not_billable')),
    hourly_rate DECIMAL(10, 2),
    is_billable BOOLEAN DEFAULT TRUE,
    -- Metadata
    custom_fields JSONB NOT NULL DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_projects_tenant ON projects(tenant_id);
CREATE INDEX idx_projects_company ON projects(company_id);
CREATE INDEX idx_projects_status ON projects(tenant_id, status);
CREATE INDEX idx_projects_manager ON projects(project_manager_id);

-- Project phases
CREATE TABLE project_phases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    sort_order INTEGER DEFAULT 0,
    start_date DATE,
    end_date DATE,
    status VARCHAR(20) DEFAULT 'not_started' CHECK (status IN ('not_started', 'in_progress', 'completed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_project_phases_project ON project_phases(project_id);

-- Task statuses
CREATE TABLE task_statuses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    color VARCHAR(7) NOT NULL,
    is_completed BOOLEAN DEFAULT FALSE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_task_statuses_tenant ON task_statuses(tenant_id);

-- Tasks
CREATE TABLE tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    phase_id UUID REFERENCES project_phases(id) ON DELETE SET NULL,
    parent_task_id UUID REFERENCES tasks(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    -- Status
    status_id UUID NOT NULL REFERENCES task_statuses(id),
    priority VARCHAR(20) DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'critical')),
    -- Assignment
    assigned_to_id UUID REFERENCES users(id),
    -- Time
    estimated_hours DECIMAL(10, 2),
    actual_hours DECIMAL(10, 2) DEFAULT 0,
    -- Dates
    start_date DATE,
    due_date DATE,
    completed_at TIMESTAMPTZ,
    -- Ordering
    sort_order INTEGER DEFAULT 0,
    -- Checklist
    checklist JSONB DEFAULT '[]',
    -- Metadata
    custom_fields JSONB NOT NULL DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tasks_tenant ON tasks(tenant_id);
CREATE INDEX idx_tasks_project ON tasks(project_id);
CREATE INDEX idx_tasks_phase ON tasks(phase_id);
CREATE INDEX idx_tasks_parent ON tasks(parent_task_id);
CREATE INDEX idx_tasks_status ON tasks(status_id);
CREATE INDEX idx_tasks_assigned ON tasks(assigned_to_id);
CREATE INDEX idx_tasks_due ON tasks(due_date) WHERE completed_at IS NULL;

-- Task dependencies
CREATE TABLE task_dependencies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    depends_on_task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    dependency_type VARCHAR(20) DEFAULT 'finish_to_start' CHECK (dependency_type IN ('finish_to_start', 'start_to_start', 'finish_to_finish')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(task_id, depends_on_task_id)
);

CREATE INDEX idx_task_deps_task ON task_dependencies(task_id);
CREATE INDEX idx_task_deps_depends ON task_dependencies(depends_on_task_id);

-- ============================================================================
-- CALENDAR & SCHEDULING
-- ============================================================================

CREATE TABLE appointments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    -- Type and associations
    appointment_type VARCHAR(20) DEFAULT 'other' CHECK (appointment_type IN ('ticket', 'project', 'meeting', 'other')),
    ticket_id UUID REFERENCES tickets(id) ON DELETE SET NULL,
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
    company_id UUID REFERENCES companies(id),
    contact_id UUID REFERENCES contacts(id),
    site_id UUID REFERENCES sites(id),
    -- Assignment
    assigned_to_id UUID NOT NULL REFERENCES users(id),
    -- Timing
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    all_day BOOLEAN DEFAULT FALSE,
    timezone VARCHAR(50) DEFAULT 'UTC',
    -- Status
    status VARCHAR(20) DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'in_progress', 'completed', 'cancelled')),
    -- Location
    location TEXT,
    -- Recurrence
    recurrence_rule TEXT,
    recurrence_parent_id UUID REFERENCES appointments(id),
    -- Reminders (in minutes before)
    reminder_minutes INTEGER[],
    -- Notes
    notes TEXT,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_appointments_tenant ON appointments(tenant_id);
CREATE INDEX idx_appointments_assigned ON appointments(assigned_to_id);
CREATE INDEX idx_appointments_start ON appointments(start_time);
CREATE INDEX idx_appointments_ticket ON appointments(ticket_id);
CREATE INDEX idx_appointments_company ON appointments(company_id);

-- User availability
CREATE TABLE user_availability (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day_of_week INTEGER NOT NULL CHECK (day_of_week >= 0 AND day_of_week <= 6),
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    is_available BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_availability_user ON user_availability(user_id);

-- Time off
CREATE TABLE time_off (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('vacation', 'sick', 'personal', 'holiday', 'other')),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    approved_by_id UUID REFERENCES users(id),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_time_off_user ON time_off(user_id);
CREATE INDEX idx_time_off_dates ON time_off(start_date, end_date);

-- On-call schedules
CREATE TABLE on_call_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    team_id UUID REFERENCES teams(id),
    rotation_type VARCHAR(20) DEFAULT 'weekly' CHECK (rotation_type IN ('weekly', 'daily', 'custom')),
    rotation_config JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_on_call_tenant ON on_call_schedules(tenant_id);

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

-- ============================================================================
-- KNOWLEDGE BASE
-- ============================================================================

-- KB categories
CREATE TABLE kb_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES kb_categories(id),
    slug VARCHAR(100) NOT NULL,
    visibility VARCHAR(20) DEFAULT 'internal' CHECK (visibility IN ('public', 'internal', 'client_specific')),
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_categories_tenant ON kb_categories(tenant_id);
CREATE INDEX idx_kb_categories_parent ON kb_categories(parent_id);
CREATE INDEX idx_kb_categories_slug ON kb_categories(tenant_id, slug);

-- KB articles
CREATE TABLE kb_articles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    summary TEXT,
    category_id UUID REFERENCES kb_categories(id),
    visibility VARCHAR(20) DEFAULT 'internal' CHECK (visibility IN ('public', 'internal', 'client_specific')),
    company_ids UUID[],
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    author_id UUID NOT NULL REFERENCES users(id),
    -- Engagement
    view_count INTEGER DEFAULT 0,
    helpful_count INTEGER DEFAULT 0,
    not_helpful_count INTEGER DEFAULT 0,
    -- Relations
    related_article_ids UUID[],
    related_ticket_ids UUID[],
    -- Metadata
    tags TEXT[] DEFAULT '{}',
    -- Publishing
    published_at TIMESTAMPTZ,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_articles_tenant ON kb_articles(tenant_id);
CREATE INDEX idx_kb_articles_category ON kb_articles(category_id);
CREATE INDEX idx_kb_articles_status ON kb_articles(tenant_id, status);
CREATE INDEX idx_kb_articles_visibility ON kb_articles(tenant_id, visibility);
CREATE INDEX idx_kb_articles_slug ON kb_articles(tenant_id, slug);
CREATE INDEX idx_kb_articles_content_trgm ON kb_articles USING gin ((title || ' ' || content) gin_trgm_ops);

-- KB article versions
CREATE TABLE kb_article_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    article_id UUID NOT NULL REFERENCES kb_articles(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    edited_by_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_versions_article ON kb_article_versions(article_id);

-- ============================================================================
-- NOTIFICATIONS
-- ============================================================================

-- Notification channels
CREATE TABLE notification_channels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel_type VARCHAR(20) NOT NULL CHECK (channel_type IN ('email', 'sms', 'slack', 'teams', 'discord', 'google_chat', 'mattermost', 'in_app')),
    name VARCHAR(100) NOT NULL,
    config_encrypted TEXT NOT NULL,
    is_active BOOLEAN DEFAULT FALSE,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_channels_tenant ON notification_channels(tenant_id);
CREATE INDEX idx_notification_channels_type ON notification_channels(tenant_id, channel_type);

-- Notification templates
CREATE TABLE notification_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    channel_type VARCHAR(20) NOT NULL,
    subject VARCHAR(255),
    body_text TEXT NOT NULL,
    body_html TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_templates_tenant ON notification_templates(tenant_id);
CREATE INDEX idx_notification_templates_event ON notification_templates(tenant_id, event_type);

-- User notification preferences
CREATE TABLE user_notification_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    channel_types VARCHAR(20)[] NOT NULL DEFAULT '{}',
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, event_type)
);

CREATE INDEX idx_notification_prefs_user ON user_notification_preferences(user_id);

-- Notifications (in-app and history)
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    channel_type VARCHAR(20) NOT NULL,
    template_id UUID REFERENCES notification_templates(id),
    recipient VARCHAR(255),
    subject VARCHAR(255),
    body TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'delivered', 'failed')),
    error_message TEXT,
    sent_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notifications_tenant ON notifications(tenant_id);
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_status ON notifications(status);
CREATE INDEX idx_notifications_user_unread ON notifications(user_id, read_at) WHERE read_at IS NULL;

-- Notification rules (for automation)
CREATE TABLE notification_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    conditions JSONB DEFAULT '{}',
    channels VARCHAR(20)[] NOT NULL,
    recipients JSONB NOT NULL,
    template_id UUID REFERENCES notification_templates(id),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_rules_tenant ON notification_rules(tenant_id);
CREATE INDEX idx_notification_rules_event ON notification_rules(tenant_id, event_type);

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

-- ============================================================================
-- AUDIT LOG
-- ============================================================================

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    action VARCHAR(20) NOT NULL CHECK (action IN ('create', 'update', 'delete', 'view', 'login', 'logout', 'export', 'import')),
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID,
    old_values JSONB,
    new_values JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_tenant ON audit_log(tenant_id);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_action ON audit_log(action);

-- ============================================================================
-- FILE STORAGE
-- ============================================================================

CREATE TABLE files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    original_name VARCHAR(255) NOT NULL,
    storage_path VARCHAR(500) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size BIGINT NOT NULL,
    checksum VARCHAR(64),
    uploaded_by_id UUID NOT NULL REFERENCES users(id),
    -- Entity association
    entity_type VARCHAR(50),
    entity_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_files_tenant ON files(tenant_id);
CREATE INDEX idx_files_entity ON files(entity_type, entity_id);

-- ============================================================================
-- SETTINGS & CONFIGURATION
-- ============================================================================

CREATE TABLE tenant_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL,
    key VARCHAR(100) NOT NULL,
    value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, category, key)
);

CREATE INDEX idx_tenant_settings_tenant ON tenant_settings(tenant_id);
CREATE INDEX idx_tenant_settings_category ON tenant_settings(tenant_id, category);

-- ============================================================================
-- MODULE CONFIGURATION (for optional modules)
-- ============================================================================

CREATE TABLE module_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    module_name VARCHAR(50) NOT NULL,
    is_enabled BOOLEAN DEFAULT FALSE,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, module_name)
);

CREATE INDEX idx_module_config_tenant ON module_config(tenant_id);

-- ============================================================================
-- UPDATED_AT TRIGGER FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to all relevant tables
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT table_name
        FROM information_schema.columns
        WHERE column_name = 'updated_at'
        AND table_schema = 'public'
    LOOP
        EXECUTE format('
            CREATE TRIGGER update_%I_updated_at
            BEFORE UPDATE ON %I
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        ', t, t);
    END LOOP;
END $$;

-- ============================================================================
-- ROW LEVEL SECURITY (for multi-tenant)
-- ============================================================================

-- Enable RLS on all tables with tenant_id
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT table_name
        FROM information_schema.columns
        WHERE column_name = 'tenant_id'
        AND table_schema = 'public'
        AND table_name != 'tenants'
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('
            CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = COALESCE(
                NULLIF(current_setting(''app.current_tenant'', true), '''')::UUID,
                tenant_id
            ))
        ', t);
    END LOOP;
END $$;

-- ============================================================================
-- DEFAULT DATA
-- ============================================================================

-- Insert a default tenant for single-tenant mode
INSERT INTO tenants (id, name, slug, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'active')
ON CONFLICT DO NOTHING;
