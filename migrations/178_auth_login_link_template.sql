-- PMS-918 followup (mokosh-contact-login prompt 010): auth.login_link template.
--
-- Prompt 010's ContactAuthService::request_login_link mints a magic-link
-- intent + dispatches an `auth.login_link` notification, but the
-- corresponding template row was never seeded. The dispatcher silently
-- no-ops when no template + rule pair matches the event type, so every
-- click on the magic-link finder page (/portal/login or /portal/find)
-- persisted an intent row and then quietly dropped the email on the
-- floor. Recipients had a magic link they never received.
--
-- Distinct from the auth.portal_grant template (migrations 144 + 146):
-- portal_grant fires at MSP-admin grant time (welcome + set-password),
-- login_link fires at RECURRING sign-in time when the recipient hit the
-- finder page themselves. Different context (no set-password link in
-- this one; the recipient is not necessarily first-run), so a dedicated
-- event keeps the wording honest.
--
-- Context contract (populated by ContactAuthService::request_login_link):
--   recipient_email  -> the caller-supplied email (whitespace-normalised)
--   magic_link_url   -> {spa_base_url}/portal/pick?token={intent.id}.{secret}
--   msp_name         -> tenant display name (branding enrichment)
--   msp_support_email
--   msp_primary_color
--   msp_logo_url

INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Portal Sign-in Link - Email',
     'auth.login_link',
     'email',
     'Sign in to your {{msp_name}} portal',
     E'Hello,\n\n'
        || E'A sign-in link was requested for your {{msp_name}} portal account. Use the link below to sign in.\n\n'
        || E'{{magic_link_url}}\n\n'
        || E'This sign-in link expires in 15 minutes. If it has expired, request a new one from the sign-in page.\n\n'
        || E'If you did not request this link, you can ignore this message. Nothing changes on your account unless the link is used.\n\n'
        || E'-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n',
     E'<!doctype html><html><body style="font-family:sans-serif;color:#111;margin:0;padding:0;">'
        || '<div style="max-width:560px;margin:0 auto;padding:24px;">'
        || '<div style="border-bottom:3px solid {{msp_primary_color}};padding-bottom:12px;margin-bottom:16px;">'
        || '<img src="{{msp_logo_url}}" alt="{{msp_name}}" style="max-height:48px;">'
        || '</div>'
        || '<h1 style="font-size:18px;margin:0 0 12px 0;">Sign in to {{msp_name}}</h1>'
        || '<p>A sign-in link was requested for your {{msp_name}} portal account. Use the button below to sign in.</p>'
        || '<p><a href="{{magic_link_url}}" style="display:inline-block;background:{{msp_primary_color}};color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Sign in to your portal</a></p>'
        || '<p style="color:#666;font-size:12px;">If the button does not work, paste this link into your browser:<br><a href="{{magic_link_url}}">{{magic_link_url}}</a></p>'
        || '<p style="color:#666;font-size:12px;">This sign-in link expires in 15 minutes. If it has expired, request a new one from the sign-in page.</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">If you did not request this link, you can ignore this message. Nothing changes on your account unless the link is used.</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.</p>'
        || '</div></body></html>',
     TRUE);

-- Rule so the dispatcher fans out. Recipients ride the dispatch context's
-- `recipient_email` field, same shape as auth.portal_grant and
-- auth.password_reset.
INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - Portal Sign-in Link - Email',
    'auth.login_link',
    ARRAY['email']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type = 'auth.login_link'
  AND t.channel_type = 'email';
