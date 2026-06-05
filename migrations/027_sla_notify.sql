-- PMS-106 follow-up: SLA at-risk / breach notifications.
--
-- Two pieces:
--   1. `sla_notifications` - a per-(ticket, kind) ledger so the
--      `sla_sweep` worker dispatches each SLA milestone exactly once.
--      The UNIQUE(ticket_id, kind) guard makes the worker idempotent:
--      it INSERTs the ledger row after dispatching and skips any
--      (ticket, kind) pair already present.
--   2. Default-tenant `notification_templates` + active
--      `notification_rules` for event_type 'sla.at_risk' and
--      'sla.breached', mirroring the transactional-event defaults in
--      021_notification_dispatcher_defaults.sql. Recipients stay empty;
--      the worker passes the ticket's assignee via
--      context.recipient_user_id and the dispatcher merges it at send
--      time. Bodies use {{key}} placeholders resolved from the dispatch
--      context (ticket_id, kind, due).

CREATE TABLE sla_notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN (
        'first_response_at_risk',
        'first_response_breached',
        'resolution_at_risk',
        'resolution_breached'
    )),
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(ticket_id, kind)
);

CREATE INDEX idx_sla_notifications_tenant ON sla_notifications(tenant_id);
CREATE INDEX idx_sla_notifications_ticket ON sla_notifications(ticket_id);

-- Default templates for the two SLA events. channel_type = 'in_app' so
-- the assignee sees the alert in their inbox without requiring an email
-- transport to be configured; the dispatcher's per-(user, event,
-- channel) preference check still applies. E'...' literals so \n is a
-- real newline at insert time.
INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html)
VALUES
    -- sla.at_risk
    ('00000000-0000-0000-0000-000000000001',
     'SLA At Risk - In App',
     'sla.at_risk',
     'in_app',
     'SLA at risk on ticket',
     E'A ticket you are assigned is approaching its SLA deadline ({{kind}}).\n\nDue: {{due}}\n',
     NULL),

    -- sla.breached
    ('00000000-0000-0000-0000-000000000001',
     'SLA Breached - In App',
     'sla.breached',
     'in_app',
     'SLA breached on ticket',
     E'A ticket you are assigned has breached its SLA ({{kind}}).\n\nDue: {{due}}\n',
     NULL);

-- One active rule per event_type, channel = in_app, recipients sourced
-- from the dispatch context (context.recipient_user_id). template_id is
-- resolved via a subquery so this migration need not know the generated
-- UUIDs.
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
  AND t.event_type IN ('sla.at_risk', 'sla.breached')
  AND t.channel_type = 'in_app';
