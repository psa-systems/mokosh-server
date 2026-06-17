-- PMS-403: scheduling templates (dispatch vs calendar).
--
-- A reusable, named scheduling shape a dispatcher can pick so that selecting a
-- template plus a start time pre-fills an appointment on the frontend
-- (e2-templates-fe / e3-templates-fe). Two kinds: `dispatch` (on-site work,
-- with optional pre/post travel buffers) and `calendar` (client interactions
-- and status updates). The template captures a default duration, type, travel
-- buffers, and optional defaults (title, location, linked ticket); it is NOT a
-- concrete appointment and has no fixed start time. Travel buffers live here
-- (the `appointments` table has no buffer columns); the frontend uses them to
-- compute the effective on-site block when a dispatch template is applied.

CREATE TABLE scheduling_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    -- dispatch = on-site work; calendar = client interactions / status updates.
    kind VARCHAR(20) NOT NULL CHECK (kind IN ('dispatch', 'calendar')),
    -- Mirrors the appointments CHECK (008_calendar.sql:13) so a template's
    -- type can be carried straight onto the appointment it pre-fills.
    appointment_type VARCHAR(20) NOT NULL DEFAULT 'other' CHECK (appointment_type IN ('ticket', 'project', 'meeting', 'other')),
    duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0),
    travel_before_minutes INTEGER NOT NULL DEFAULT 0 CHECK (travel_before_minutes >= 0),
    travel_after_minutes INTEGER NOT NULL DEFAULT 0 CHECK (travel_after_minutes >= 0),
    default_title VARCHAR(255),
    default_location TEXT,
    default_ticket_id UUID REFERENCES tickets(id) ON DELETE SET NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scheduling_templates_tenant ON scheduling_templates(tenant_id);

-- updated_at trigger. 024's trigger loop already ran, so a table created now
-- does NOT inherit it; attach explicitly (mirrors 051's mileage_entries).
CREATE TRIGGER update_scheduling_templates_updated_at
    BEFORE UPDATE ON scheduling_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Row-level security. The fail-closed `tenant_isolation` policy is attached by
-- a DO-block loop over `information_schema` in 024/038, but those loops already
-- ran, so a table created now does NOT inherit the policy. Attach the same
-- fail-closed, FORCE'd policy explicitly (PMS-257 posture) so
-- scheduling_templates is tenant-isolated the moment the application drops its
-- BYPASSRLS role. The GUC is set transaction-locally by
-- `Database::begin_with_tenant`.
ALTER TABLE scheduling_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduling_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scheduling_templates
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
