-- MAPPS-650 / PMS-946: rename the visible "Portal ID" copy in the
-- `auth.portal_grant` email to "Company ID". Internal placeholder
-- name `{{portal_id}}` stays unchanged so the render context on the
-- server (see `ContactService::send_grant_email`) needs no code
-- change; only the surrounding template body flips vocab.
--
-- David explicitly asked for "Company ID" as the user-facing name
-- during the 2026-08-27 standup (see PMS-946): the CRM's top-level
-- client entity is already called a Company, and "Company ID" reads
-- customer-neutral without leaking MSP jargon.
--
-- Migration 146 stays immutable. This migration re-issues the UPDATE
-- against the same row, so the template picks up the new copy on the
-- next deploy without a new event_type / rule pair. Idempotent by
-- construction (the row it targets is uniquely identified by
-- (tenant_id, event_type, channel_type)); running it twice is a no-op.
--
-- Rollback: revert by UPDATEing the same row back to migration 146's
-- shape (see git log at that migration for the pre-650 body). A
-- future rename (say, "Client ID") should ship as its own migration
-- following this same pattern.

UPDATE notification_templates
   SET body_text =
           E'Hello {{display_name}},\n\n'
        || E'You have been granted access to your {{msp_name}} client portal.\n\n'
        || E'Your Company ID: {{portal_id}}\n\n'
        || E'Use the link below to sign in.\n\n'
        || E'{{magic_link_url}}\n\n'
        || E'This sign-in link expires in 15 minutes. If it has expired, request a new one from the sign-in page.\n\n'
        || E'Prefer a password? Set one here instead (link valid for 72 hours):\n\n'
        || E'{{password_setup_link}}\n\n'
        || E'-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n',
       body_html =
           E'<!doctype html><html><body style="font-family:sans-serif;color:#111;margin:0;padding:0;">'
        || '<div style="max-width:560px;margin:0 auto;padding:24px;">'
        || '<div style="border-bottom:3px solid {{msp_primary_color}};padding-bottom:12px;margin-bottom:16px;">'
        || '<img src="{{msp_logo_url}}" alt="{{msp_name}}" style="max-height:48px;">'
        || '</div>'
        || '<h1 style="font-size:18px;margin:0 0 12px 0;">Sign in to {{msp_name}}</h1>'
        || '<p>Hello {{display_name}},</p>'
        || '<p>You have been granted access to your {{msp_name}} client portal.</p>'
        || '<p style="background:#f4f4f5;border:1px solid #e4e4e7;border-radius:6px;padding:12px 16px;font-size:15px;">'
        || '<strong>Your Company ID:</strong> <span style="font-family:monospace;font-size:17px;letter-spacing:1px;">{{portal_id}}</span>'
        || '</p>'
        || '<p><a href="{{magic_link_url}}" style="display:inline-block;background:{{msp_primary_color}};color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Sign in to your portal</a></p>'
        || '<p style="color:#666;font-size:12px;">If the button does not work, paste this link into your browser:<br><a href="{{magic_link_url}}">{{magic_link_url}}</a></p>'
        || '<p style="color:#666;font-size:12px;">This sign-in link expires in 15 minutes. If it has expired, request a new one from the sign-in page.</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:13px;">Prefer a password? <a href="{{password_setup_link}}">Set one here instead</a> (link valid for 72 hours).</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.</p>'
        || '</div></body></html>'
 WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
   AND event_type = 'auth.portal_grant'
   AND channel_type = 'email';
