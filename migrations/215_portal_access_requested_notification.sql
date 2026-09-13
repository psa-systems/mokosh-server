-- PMS-1187: the MSP is told when a customer asks for access.
--
-- Its own event type and its own template, never a conditional inside an
-- existing one. `notifications::render_template` is a flat `{{key}}` replacer
-- with no conditionals, so a template serving two audiences emits an
-- unsupplied key verbatim into somebody's inbox - the rule migration 206
-- states and migration 152 proved by trying the other way.
--
-- This mail serves the MSP, so it names the product the way every other
-- staff-facing mail does; the customer never receives it.
--
-- Seeded for the default tenant (the pattern of migration 021), backfilled
-- into every existing tenant, and added to the copy list in
-- `TenantService::seed_default_config` so a new tenant gets it. A template
-- with no rule is a message that is never sent (PMS-761), so it gets both.
--
-- Context supplied by `ContactAuthService::request_access`:
--   {{contact_name}}   who asked
--   {{contact_email}}  how to reach them
--   {{company_name}}   which customer
--   {{area}}           what they could not reach, in the customer's words
--   {{note}}           what they said, or a stated absence (composed in Rust,
--                      because the renderer cannot express "if empty")
--   {{contact_url}}    where staff answer it

BEGIN;

INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Portal Access Requested - Email',
     'portal.access_requested',
     'email',
     '{{contact_name}} asked for access to {{area}}',
     E'{{contact_name}} ({{contact_email}}) at {{company_name}} asked for access to {{area}} in their portal.\n\n'
        || E'{{note}}\n\n'
        || E'Open their contact record to grant it:\n\n'
        || E'{{contact_url}}\n',
     '<!doctype html><html><body>'
        || '<p><strong>{{contact_name}}</strong> ({{contact_email}}) at {{company_name}} asked for access to {{area}} in their portal.</p>'
        || '<p>{{note}}</p>'
        || '<p><a href="{{contact_url}}">Open their contact record to grant it</a></p>'
        || '</body></html>',
     TRUE);

-- The rule. Recipients are empty by default and the dispatch supplies the
-- company's account manager as `recipient_user_id`; a tenant adds whoever else
-- should hear about it in the notification settings. A company with no account
-- manager and an unconfigured rule mails nobody, and the request is still on
-- the contact record where staff answer it.
INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - Portal Access Requested - Email',
    t.event_type,
    ARRAY['email']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type = 'portal.access_requested'
  AND t.channel_type = 'email';

-- Backfill every tenant that already exists, the shape of migration 206.
-- Without this, a tenant provisioned before today has no rule for the event,
-- `dispatch` iterates rules, and the mail silently never goes.
DO $$
DECLARE
    default_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000001';
BEGIN
    INSERT INTO notification_templates
        (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
    SELECT t.id, src.name, src.event_type, src.channel_type,
           src.subject, src.body_text, src.body_html, src.is_active
    FROM tenants t
    CROSS JOIN notification_templates src
    WHERE src.tenant_id = default_tenant
      AND src.event_type = 'portal.access_requested'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1 FROM notification_templates existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = src.event_type
            AND existing.channel_type = src.channel_type
      );

    INSERT INTO notification_rules
        (tenant_id, name, event_type, channels, recipients, template_id, is_active)
    SELECT t.id, r.name, r.event_type, r.channels, r.recipients, nt.id, r.is_active
    FROM tenants t
    CROSS JOIN notification_rules r
    JOIN notification_templates ot ON ot.id = r.template_id
    JOIN notification_templates nt
      ON nt.tenant_id = t.id
     AND nt.event_type = ot.event_type
     AND nt.channel_type = ot.channel_type
    WHERE r.tenant_id = default_tenant
      AND r.event_type = 'portal.access_requested'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1 FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
      );
END $$;

COMMIT;
