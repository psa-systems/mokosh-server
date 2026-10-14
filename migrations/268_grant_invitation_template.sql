-- PMS-1208: seed the `auth.mokosh_grant_invite` notification template.
--
-- Separate migration from 222 (the invitations table) so the schema
-- change and the seed data are reversible independently, and so
-- `TenantService::seed_default_config` (which copies the default-
-- tenant templates into each new tenant) picks up the seed on the
-- next tenant creation without needing to re-read the table shape.
--
-- Context contract, populated by `GrantInvitationsService::create` -
-- see also PMS-1140 (the "one audience per template" rule) which is
-- what stops this from being folded into `auth.welcome` or
-- `auth.portal_grant`. This template targets a BUNYIP user being
-- invited to see another Bunyip user's Mokosh account:
--
--   `invitee_display_name`   -> the invitee's display name if resolved
--                               through bunyip userinfo, else the local
--                               part of `invitee_email`
--   `inviter_display_name`   -> the inviter's display name (users row)
--   `mokosh_account_name`    -> tenant name being shared
--   `role_display`           -> human role label ("Manager", not
--                               "manager"); the service maps the
--                               vocab
--   `accept_url`             -> mokosh-apps origin plus
--                               `/accept-grant?token=<plaintext>`;
--                               the mokosh-apps route resolves the
--                               token via the `by-token` endpoint
--   `expires_at_human`       -> "in 7 days" or an absolute date
--                               ("March 15"); rendered by the service
--                               so the template stays a flat replacer
--   `app_name`               -> branded product name

INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Mokosh account invitation - Email',
     'auth.mokosh_grant_invite',
     'email',
     '{{inviter_display_name}} invited you to {{mokosh_account_name}} on {{app_name}}',
     E'Hello {{invitee_display_name}},\n\n'
        || E'{{inviter_display_name}} has invited you to access {{mokosh_account_name}} on {{app_name}} as {{role_display}}.\n\n'
        || E'Accept the invitation:\n{{accept_url}}\n\n'
        || E'The invitation expires {{expires_at_human}}. You can decline from the same link.\n\n'
        || E'If you do not know {{inviter_display_name}} or did not expect this invitation, you can safely ignore this email.\n',
     E'<!doctype html><html><body style="font-family:sans-serif;color:#111;margin:0;padding:0;">'
        || '<div style="max-width:560px;margin:0 auto;padding:24px;">'
        || '<h1 style="font-size:18px;margin:0 0 12px 0;">You have been invited to {{mokosh_account_name}}</h1>'
        || '<p>Hello {{invitee_display_name}},</p>'
        || '<p><strong>{{inviter_display_name}}</strong> has invited you to access <strong>{{mokosh_account_name}}</strong> on {{app_name}} as <strong>{{role_display}}</strong>.</p>'
        || '<p><a href="{{accept_url}}" style="display:inline-block;background:#2f4e2e;color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Accept invitation</a></p>'
        || '<p style="color:#666;font-size:12px;">If the button does not work, paste this link into your browser:<br><a href="{{accept_url}}">{{accept_url}}</a></p>'
        || '<p style="color:#666;font-size:12px;">The invitation expires {{expires_at_human}}. You can decline from the same link.</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">If you do not know {{inviter_display_name}} or did not expect this invitation, you can safely ignore this email.</p>'
        || '</div></body></html>',
     TRUE);

INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - Mokosh account invitation - Email',
    'auth.mokosh_grant_invite',
    ARRAY['email']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type = 'auth.mokosh_grant_invite'
  AND t.channel_type = 'email';

-- Backfill for existing tenants: same shape migration 206 uses so an
-- older tenant that upgrades to this migration can dispatch the
-- invitation email from day one instead of waiting for its next
-- create-tenant call to bring in the template. `seed_default_config`
-- already carries the equivalent copy path for tenants created from
-- now on.
DO $$
DECLARE
    default_tenant CONSTANT UUID := '00000000-0000-0000-0000-000000000001'::uuid;
BEGIN
    INSERT INTO notification_templates
        (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
    SELECT t.id, src.name, src.event_type, src.channel_type,
           src.subject, src.body_text, src.body_html, src.is_active
    FROM tenants t
    CROSS JOIN notification_templates src
    WHERE src.tenant_id = default_tenant
      AND src.event_type = 'auth.mokosh_grant_invite'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1 FROM notification_templates existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = 'auth.mokosh_grant_invite'
            AND existing.channel_type = src.channel_type
      );

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
      AND r.event_type = 'auth.mokosh_grant_invite'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1 FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = 'auth.mokosh_grant_invite'
      );
END $$;
