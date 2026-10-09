-- PMS-1378: route the team invite and the quote-send email through
-- NotificationsService::dispatch instead of a direct INSERT or a direct
-- mailer call, so the SPA preview button (`POST /notifications/preview`)
-- shows what the recipient will actually read.
--
-- Seeds two event types on the default tenant:
--
--   invitations.created  - sent by InvitationsService::create when a team
--                          invite is accepted by email. Login-driven
--                          acceptance (PMS-244): the link is the Mokosh
--                          login, not a per-invite accept URL.
--   quote.sent           - sent by QuoteService::mail_quote_to_client on
--                          the sent transition. The portal link is a
--                          per-tenant login URL plus `?next=/quotes/{id}`
--                          (MAPPS-779).
--
-- Bodies carry the same wording the two hardcoded paths spell out today,
-- with `{{key}}` placeholders the dispatcher resolves from the context JSON.
-- E'...' literals so `\n` becomes a real newline, matching migration 021.
--
-- Fan-out to every pre-existing tenant with the NOT EXISTS shape from
-- migration 030, so a tenant on main the day this migration runs gets both
-- rows on the next boot (new tenants inherit through
-- `TenantService::copy_default_config`, which already copies templates +
-- rules keyed by `event_type`).

-- Default-tenant templates.
INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Team Invitation - Email',
     'invitations.created',
     'email',
     'You have been invited to {{tenant_name}} on {{app_name}}',
     E'You have been invited to join {{tenant_name}} on {{app_name}} as a {{role}}.\n\nSign in to accept the invitation:\n{{app_url}}\n\nThe invitation expires in {{ttl_days}} days. If you did not expect this, you can ignore this email.\n',
     NULL),

    ('00000000-0000-0000-0000-000000000001',
     'Quote Sent - Email',
     'quote.sent',
     'email',
     'Quote {{quote_number}} from {{sender_org_name}} for your approval',
     E'{{sender_org_name}} has sent you a quote for your approval.\n\nQuote: {{quote_number}}\nTitle: {{title}}\nTotal: {{total}}\nValid until: {{valid_until}}\n\nReview and respond:\n{{portal_link}}\n\n{{sender_contact_line}}\n',
     NULL);

-- Default-tenant rules. Recipients are empty: the dispatcher merges
-- `context.recipient_email` into fanout at send time, same posture as the
-- auth / ticket rows migration 021 seeded.
INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - ' || t.name,
    t.event_type,
    ARRAY['email']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type IN ('invitations.created', 'quote.sent')
  AND t.channel_type = 'email';

-- Fan-out: give every pre-existing tenant the same two templates and rules
-- the default tenant now holds, guarded by NOT EXISTS so a re-run is a
-- no-op and a tenant that already carries them is skipped. Matches the
-- shape migration 030 uses.
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
      AND src.event_type IN ('invitations.created', 'quote.sent')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_templates dst
          WHERE dst.tenant_id = t.id
            AND dst.event_type = src.event_type
            AND dst.channel_type = src.channel_type
      );

    INSERT INTO notification_rules
        (tenant_id, name, event_type, channels, recipients, template_id, is_active)
    SELECT t.id,
           'Default - ' || dst_tpl.name,
           dst_tpl.event_type,
           ARRAY['email']::VARCHAR(20)[],
           '{"user_ids": [], "emails": []}'::jsonb,
           dst_tpl.id,
           TRUE
    FROM tenants t
    JOIN notification_templates dst_tpl
      ON dst_tpl.tenant_id = t.id
     AND dst_tpl.event_type IN ('invitations.created', 'quote.sent')
     AND dst_tpl.channel_type = 'email'
    WHERE t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_rules dst
          WHERE dst.tenant_id = t.id
            AND dst.event_type = dst_tpl.event_type
            AND dst.channels @> ARRAY['email']::VARCHAR(20)[]
      );
END $$;
