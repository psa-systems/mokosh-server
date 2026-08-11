-- PMS-761: the public ticket-note email names the MSP, and reaches every
-- tenant rather than only the seeded default one.
--
-- Two separate defects, both fixed here because either one alone leaves the
-- feature broken.
--
-- 1. The body said "A new update has been added to ticket TCK-1042" and
--    nothing else. The recipient is a client contact, so the message named
--    neither the organisation writing to them nor a way to ask about it.
--    `{{org_name}}` and `{{contact_line}}` are supplied by
--    `TicketsService::send_note_email` from `OrgIdentity`; `contact_line` is
--    never empty, so no conditional is needed (the renderer has none).
--
-- 2. `ticket.note_added` was seeded by migration 021 for the default tenant
--    only, and unlike appointment/SLA (030), auth (097) and the request link
--    (101) it never got a backfill, nor a place in
--    `TenantService::copy_default_config`. `dispatch` resolves rules by
--    (tenant_id, event_type) and skips silently when there are none, so for
--    every real tenant the note email fanned out to zero recipients while the
--    note row was still stamped `is_email_sent = TRUE`. The UI has been
--    reporting delivery of messages that were never sent.
--
-- Idempotency: the UPDATE is guarded on the exact previous body, so a tenant
-- that has edited its own copy keeps it; the INSERTs are NOT EXISTS-guarded on
-- the same keys as migrations 030 / 097.

DO $$
DECLARE
    default_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000001';
BEGIN
    -- (1) Re-word the source copy first, so the backfill below hands new
    -- tenants the new wording rather than seeding the anonymous one and
    -- needing a second pass.
    UPDATE notification_templates
    SET body_text = E'{{org_name}} has added an update to ticket {{ticket_number}}:\n\n{{content}}\n\n{{contact_line}}\n',
        updated_at = NOW()
    WHERE event_type = 'ticket.note_added'
      AND channel_type = 'email'
      AND body_text = E'A new update has been added to ticket {{ticket_number}}:\n\n{{content}}\n';

    -- (2) Every tenant that has no template for this event gets the default
    -- tenant's, exactly as 097 does for the auth templates.
    INSERT INTO notification_templates
        (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
    SELECT t.id, src.name, src.event_type, src.channel_type,
           src.subject, src.body_text, src.body_html, src.is_active
    FROM tenants t
    CROSS JOIN notification_templates src
    WHERE src.tenant_id = default_tenant
      AND src.event_type = 'ticket.note_added'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_templates existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = src.event_type
            AND existing.channel_type = src.channel_type
      );

    -- ...and the rule that points at it. Without this the template is present
    -- and unreachable: `dispatch` iterates rules, not templates.
    INSERT INTO notification_rules
        (tenant_id, name, event_type, channels, recipients, template_id, is_active)
    SELECT t.id, r.name, r.event_type, r.channels, r.recipients, nt.id, r.is_active
    FROM tenants t
    CROSS JOIN notification_rules r
    JOIN notification_templates ot
      ON ot.id = r.template_id AND ot.tenant_id = default_tenant
    JOIN notification_templates nt
      ON nt.tenant_id = t.id
     AND nt.event_type = ot.event_type
     AND nt.channel_type = ot.channel_type
    WHERE r.tenant_id = default_tenant
      AND r.event_type = 'ticket.note_added'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
            AND existing.template_id = nt.id
      );

    -- The same gap for the request-form link, which migration 101 backfilled
    -- for the tenants that existed then. `copy_default_config` copies its
    -- TEMPLATE but not its RULE, so any tenant created since has had the
    -- template sitting unreachable and has sent no request-form email at all.
    -- The service-side fix goes in with this migration; this covers the
    -- tenants already created without it.
    INSERT INTO notification_rules
        (tenant_id, name, event_type, channels, recipients, template_id, is_active)
    SELECT t.id, r.name, r.event_type, r.channels, r.recipients, nt.id, r.is_active
    FROM tenants t
    CROSS JOIN notification_rules r
    JOIN notification_templates ot
      ON ot.id = r.template_id AND ot.tenant_id = default_tenant
    JOIN notification_templates nt
      ON nt.tenant_id = t.id
     AND nt.event_type = ot.event_type
     AND nt.channel_type = ot.channel_type
    WHERE r.tenant_id = default_tenant
      AND r.event_type = 'forms.request_link'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
            AND existing.template_id = nt.id
      );
END $$;
