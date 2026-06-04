-- PMS-128 split: appointments, availability, time off, on-call.

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
