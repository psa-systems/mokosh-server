-- PMS-918 (mokosh-contact-login prompt 010): auth.portal_grant template.
--
-- The pre-pivot grant email (`auth.welcome`, migration 021 seed + branding
-- rewrites in migrations 097/110/123) offered exactly one CTA: the
-- `/portal/{slug}/set-password?token=...` link. Prompt 010 makes
-- magic-link the default first-run experience, so the grant email now
-- carries two blocks - a primary "Sign in" magic-link button + a smaller
-- "Prefer a password?" secondary link. Both tokens are minted at grant
-- time and land in the same message.
--
-- A dedicated event type (rather than folding the second link into
-- `auth.welcome`) keeps this concern separate from the staff-side
-- MSP-admin welcome email that also uses `auth.welcome`. It also keeps
-- `notifications::render_template` (a flat `{{key}}` replacer, no
-- conditionals) from having to branch on whether `magic_link_url` was
-- supplied.
--
-- Context contract (populated by `ContactService::send_grant_email`):
--   `display_name`         -> the contact's first name
--   `msp_name`             -> tenant display name (auto-injected by
--                             `NotificationsService::dispatch` via the
--                             MSP-branding enrichment)
--   `msp_support_email`    -> same source as above
--   `msp_primary_color`    -> same source as above
--   `magic_link_url`       -> `{spa_base_url}/portal/pick?token={intent.id}.{secret}`
--   `password_setup_link`  -> `{spa_base_url}/portal/{slug}/set-password?token={contact.id}.{secret}`

INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Portal Access Granted - Email',
     'auth.portal_grant',
     'email',
     'Sign in to your {{msp_name}} portal',
     E'Hello {{display_name}},\n\n'
        || E'You have been granted access to your {{msp_name}} client portal. Use the link below to sign in.\n\n'
        || E'{{magic_link_url}}\n\n'
        || E'This sign-in link expires in 15 minutes. If it has expired, request a new one from the sign-in page.\n\n'
        || E'Prefer a password? Set one here instead (link valid for 72 hours):\n\n'
        || E'{{password_setup_link}}\n\n'
        || E'-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n',
     E'<!doctype html><html><body style="font-family:sans-serif;color:#111;margin:0;padding:0;">'
        || '<div style="max-width:560px;margin:0 auto;padding:24px;">'
        || '<div style="border-bottom:3px solid {{msp_primary_color}};padding-bottom:12px;margin-bottom:16px;">'
        || '<img src="{{msp_logo_url}}" alt="{{msp_name}}" style="max-height:48px;">'
        || '</div>'
        || '<h1 style="font-size:18px;margin:0 0 12px 0;">Sign in to {{msp_name}}</h1>'
        || '<p>Hello {{display_name}},</p>'
        || '<p>You have been granted access to your {{msp_name}} client portal. Use the button below to sign in.</p>'
        || '<p><a href="{{magic_link_url}}" style="display:inline-block;background:{{msp_primary_color}};color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Sign in to your portal</a></p>'
        || '<p style="color:#666;font-size:12px;">If the button does not work, paste this link into your browser:<br><a href="{{magic_link_url}}">{{magic_link_url}}</a></p>'
        || '<p style="color:#666;font-size:12px;">This sign-in link expires in 15 minutes. If it has expired, request a new one from the sign-in page.</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:13px;">Prefer a password? <a href="{{password_setup_link}}">Set one here instead</a> (link valid for 72 hours).</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.</p>'
        || '</div></body></html>',
     TRUE);

-- Rule so the dispatcher fans out. Recipients are sourced from the
-- caller-supplied `recipient_email` on the dispatch context (same shape
-- as auth.welcome + auth.password_reset).
INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - Portal Access Granted - Email',
    'auth.portal_grant',
    ARRAY['email']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type = 'auth.portal_grant'
  AND t.channel_type = 'email';
