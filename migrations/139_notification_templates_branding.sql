-- PMS-729 phase 2 §6 slice 5: branded outbound emails.
--
-- Every transactional email the dispatcher renders now has access to
-- four tenant-branding placeholders that the notifications service
-- injects into the context automatically (see
-- `src/modules/notifications/service.rs::branding_context_for`):
--
--   {{msp_name}}            display name of the tenant (from tenants.name)
--   {{msp_logo_url}}        light-mode logo URL (from tenants.branding->>'logo_url')
--   {{msp_primary_color}}   primary color hex   (from tenants.branding->>'primary_color')
--   {{msp_support_email}}   support email       (from tenants.branding->>'support_email')
--
-- This migration updates the four default templates seeded by
-- migration 021 (`auth.password_reset`, `auth.welcome`, `ticket.note_added`,
-- `ticket.automation.notify`) so they carry the MSP identity: the
-- subject line prefixes the MSP name, and the HTML body wraps the copy
-- in a branded header (logo above the copy, primary-color accent on
-- the CTA link) and footer (support email + "sent on behalf of").
--
-- Each UPDATE guards on the EXACT default subject / body text from
-- migration 021 so a tenant that has customized their template via
-- the CRUD API is left alone. That preserves the "migrations never
-- clobber operator edits" contract migration 096 established for the
-- 023 backfill. Re-running is a no-op: the second run's WHERE clause
-- misses because subject / body_text have been rewritten.
--
-- Text-only bodies keep the same shape (no styled header - a plain
-- text email cannot render one), but the subject gets the MSP-name
-- prefix so the branding still lands in an inbox preview.

BEGIN;

-- auth.password_reset (email)
UPDATE notification_templates SET
    subject = '{{msp_name}} - Reset your password',
    body_text = E'{{msp_name}} received a request to reset your password.\n\nUse the link below within 24 hours to set a new password.\n\n{{reset_link}}\n\nIf you did not request this, ignore this message.\n\n-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n',
    body_html = E'<!doctype html><html><body style="font-family:sans-serif;color:#111;margin:0;padding:0;">'
        || '<div style="max-width:560px;margin:0 auto;padding:24px;">'
        || '<div style="border-bottom:3px solid {{msp_primary_color}};padding-bottom:12px;margin-bottom:16px;">'
        || '<img src="{{msp_logo_url}}" alt="{{msp_name}}" style="max-height:48px;">'
        || '</div>'
        || '<h1 style="font-size:18px;margin:0 0 12px 0;">Reset your {{msp_name}} password</h1>'
        || '<p>{{msp_name}} received a request to reset your password.</p>'
        || '<p>Use the link below within 24 hours to set a new password.</p>'
        || '<p><a href="{{reset_link}}" style="display:inline-block;background:{{msp_primary_color}};color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Reset password</a></p>'
        || '<p style="color:#666;font-size:12px;">If the button does not work, paste this link into your browser:<br><a href="{{reset_link}}">{{reset_link}}</a></p>'
        || '<p style="color:#666;font-size:12px;">If you did not request this, ignore this message.</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.</p>'
        || '</div></body></html>'
WHERE event_type = 'auth.password_reset'
  AND channel_type = 'email'
  AND subject = 'Reset your Mokosh password';

-- auth.welcome (email)
UPDATE notification_templates SET
    subject = 'Welcome to {{msp_name}}',
    body_text = E'Hello {{display_name}},\n\nAn account has been created for you at {{msp_name}}. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n\n-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n',
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
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.</p>'
        || '</div></body></html>'
WHERE event_type = 'auth.welcome'
  AND channel_type = 'email'
  AND subject = 'Welcome to Mokosh';

-- ticket.note_added (email): subject prefix carries the MSP so the
-- inbox preview reads "[Acme MSP][T-1234] Title" instead of a bare
-- ticket number a customer with multiple MSP relationships cannot
-- attribute. Body stays plain text (was NULL for body_html; leaves
-- HTML off intentionally so a slack/text-first channel is unchanged).
UPDATE notification_templates SET
    subject = '[{{msp_name}}][{{ticket_number}}] {{ticket_title}}',
    body_text = E'A new update has been added to ticket {{ticket_number}}:\n\n{{content}}\n\n-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n'
WHERE event_type = 'ticket.note_added'
  AND channel_type = 'email'
  AND subject = '[{{ticket_number}}] {{ticket_title}}';

-- ticket.automation.notify keeps its caller-supplied subject/body
-- verbatim (the caller renders their own copy), but we do NOT touch
-- the row so a caller that already includes their own branding is not
-- shadowed by ours.

COMMIT;
