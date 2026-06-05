-- PMS-58 follow-up: appointment reminders.
--
-- Two parts:
--   1. The `appointment_reminders` dedupe ledger. The reminder worker
--      stamps one row per (appointment, concrete occurrence start,
--      reminder offset) the first time that reminder fires, so a virtual
--      recurring occurrence is reminded exactly once per offset even
--      across overlapping ticks or multiple worker replicas. The UNIQUE
--      constraint is the dedupe key the worker's `ON CONFLICT DO NOTHING`
--      races against.
--   2. A default-tenant notification_template + active notification_rule
--      for event_type 'appointment.reminder', matching the shape the
--      transactional auth/ticket events use (recipients empty; the worker
--      supplies context.recipient_user_id = the appointment assignee).
--      Sent in-app so it works in any deployment without SMTP configured.

-- ============================================================================
-- APPOINTMENT REMINDER LEDGER
-- ============================================================================

CREATE TABLE appointment_reminders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    appointment_id UUID NOT NULL,
    occurrence_start TIMESTAMPTZ NOT NULL,
    reminder_minutes INTEGER NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (appointment_id, occurrence_start, reminder_minutes)
);

CREATE INDEX idx_appointment_reminders_tenant ON appointment_reminders(tenant_id);
CREATE INDEX idx_appointment_reminders_appointment ON appointment_reminders(appointment_id);

-- ============================================================================
-- DEFAULT 'appointment.reminder' TEMPLATE + RULE (default tenant)
-- ============================================================================

-- Mirrors migration 021's transactional seed: body_text is NOT NULL and
-- uses {{key}} placeholders the dispatcher resolves from the worker's
-- context JSON. E'...' so \n is a real newline at insert time. channel
-- is in_app, so the dispatcher delivers via a DB row flip (no SMTP).
INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Appointment Reminder - In-App',
     'appointment.reminder',
     'in_app',
     'Upcoming appointment reminder',
     E'You have an upcoming appointment starting at {{start}}.\n',
     NULL);

-- One active rule, channel=in_app, recipients sourced from the dispatch
-- context (worker passes recipient_user_id = appointment assignee).
-- template_id resolved via subquery so the generated UUID need not be
-- known here.
INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - ' || t.name,
    t.event_type,
    ARRAY['in_app']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type = 'appointment.reminder'
  AND t.channel_type = 'in_app';
