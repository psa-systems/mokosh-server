-- Add a client-portal URL callout to the auth.welcome template.
--
-- `TenantService::send_admin_welcome` (per migration-121-era changes)
-- computes a `client_portal_url` (`https://{slug}.<portal_host_suffix>`)
-- and stamps it into the render context, but the seed template shipped
-- by migration 110 doesn't reference it - so a fresh MSP admin's
-- welcome email tells them how to set THEIR password without saying
-- anything about the URL to give THEIR clients.
--
-- Widens both the text and HTML bodies with a minijinja `{% if %}`
-- block that renders the portal-URL callout only when the context
-- supplied one. Same guarded update posture as migration 110: WHERE
-- clause pins the exact prior body text so an operator that has
-- customised their template is left alone; the second run misses.
--
-- Two flavours of tenant get the auth.welcome fanout:
-- (1) fresh MSP admin (TenantService::send_admin_welcome, context has
--     `client_portal_url`) - the URL block renders
-- (2) per-contact portal invite (ContactService, PortalAuthService)
--     which does not send `client_portal_url`; the block hides
-- so one template body covers both cases without a schema split.
--
-- Migration is idempotent + immutable (subsequent runs match zero
-- rows because the guarded WHERE fails once the body is rewritten).

BEGIN;

-- Rebuild the text body: original wording + a trailing "Once you're
-- signed in..." paragraph guarded on `client_portal_url` being set.
UPDATE notification_templates SET
    body_text = E'Hello {{display_name}},\n\n'
        || E'An account has been created for you at {{msp_name}}. '
        || E'Use the link below to set your password and finish signing in.\n\n'
        || E'{{setup_link}}\n\n'
        || E'{% if client_portal_url %}Once you are signed in you can invite your clients to their portal at:\n\n'
        || E'{{client_portal_url}}\n\n{% endif %}'
        || E'-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n'
WHERE event_type = 'auth.welcome'
  AND channel_type = 'email'
  AND body_text = E'Hello {{display_name}},\n\nAn account has been created for you at {{msp_name}}. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n\n-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n';

-- Rebuild the HTML body: same posture, block wrapped so operators
-- who never sent an admin welcome do not see an empty section.
UPDATE notification_templates SET
    body_html = E'<!doctype html><html><body style="font-family:sans-serif;color:#111;margin:0;padding:0;">'
        || '<div style="max-width:560px;margin:0 auto;padding:24px;">'
        || '<div style="border-bottom:3px solid {{msp_primary_color}};padding-bottom:12px;margin-bottom:16px;">'
        || '<img src="{{msp_logo_url}}" alt="{{msp_name}}" style="max-height:48px;">'
        || '</div>'
        || '<h1 style="font-size:18px;margin:0 0 12px 0;">Welcome to {{msp_name}}</h1>'
        || '<p>Hello {{display_name}},</p>'
        || '<p>An account has been created for you at {{msp_name}}. Use the link below to set your password and finish signing in.</p>'
        || '<p><a href="{{setup_link}}" style="display:inline-block;background:{{msp_primary_color}};color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Set your password</a></p>'
        || '<p style="color:#666;font-size:12px;">If the button does not work, paste this link into your browser:<br><a href="{{setup_link}}">{{setup_link}}</a></p>'
        || '{% if client_portal_url %}'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p>Once you are signed in you can invite your clients to their own portal at:</p>'
        || '<p><a href="{{client_portal_url}}" style="font-family:monospace;color:{{msp_primary_color}};">{{client_portal_url}}</a></p>'
        || '{% endif %}'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.</p>'
        || '</div></body></html>'
WHERE event_type = 'auth.welcome'
  AND channel_type = 'email'
  AND body_html = E'<!doctype html><html><body style="font-family:sans-serif;color:#111;margin:0;padding:0;">'
    || '<div style="max-width:560px;margin:0 auto;padding:24px;">'
    || '<div style="border-bottom:3px solid {{msp_primary_color}};padding-bottom:12px;margin-bottom:16px;">'
    || '<img src="{{msp_logo_url}}" alt="{{msp_name}}" style="max-height:48px;">'
    || '</div>'
    || '<h1 style="font-size:18px;margin:0 0 12px 0;">Welcome to {{msp_name}}</h1>'
    || '<p>Hello {{display_name}},</p>'
    || '<p>An account has been created for you at {{msp_name}}. Use the link below to set your password and finish signing in.</p>'
    || '<p><a href="{{setup_link}}" style="display:inline-block;background:{{msp_primary_color}};color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Set your password</a></p>'
    || '<p style="color:#666;font-size:12px;">If the button does not work, paste this link into your browser:<br><a href="{{setup_link}}">{{setup_link}}</a></p>'
    || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
    || '<p style="color:#666;font-size:12px;">Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.</p>'
    || '</div></body></html>';

COMMIT;
