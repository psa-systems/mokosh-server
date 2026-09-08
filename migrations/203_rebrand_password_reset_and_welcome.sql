-- PMS-1124: the password-reset and welcome mail carry the MSP branding
-- migration 139 was written to give them.
--
-- 139 guarded its `auth.password_reset` and `auth.welcome` UPDATEs on the
-- migration 021 subjects ('Reset your Mokosh password', 'Welcome to Mokosh'),
-- but migration 116 (PMS-789) had already rewritten both to `{{app_name}}`.
-- Migrations apply in numeric order, so 116 always runs first and both of
-- 139's UPDATEs match zero rows on every database. Confirmed by applying every
-- migration to an empty database and reading the result back:
--
--   psql -d <fresh> -c "SELECT event_type, subject FROM notification_templates
--     WHERE event_type IN ('auth.password_reset','auth.welcome')
--       AND channel_type = 'email'"
--   -> 'Reset your {{app_name}} password' / 'Welcome to {{app_name}}'
--
-- The failure cascaded once more: migration 152 (the welcome mail's
-- client-portal paragraph) guards on 139's OUTPUT, so it matched zero rows
-- too. The target text for `auth.welcome` below is therefore 152's, not 139's
-- - 152 will never run again, so restoring 139's version alone would drop the
-- paragraph permanently.
--
-- Consequence this fixes: every tenant's password-reset and welcome mail went
-- out with no `{{msp_name}}` in the subject, no logo header, no accent colour
-- and no support address in the footer. `ticket.note_added` was unaffected
-- (116 did not touch it), which is why the other two tests in
-- tests/notifications_branding.rs passed and the gap went unseen.
--
-- Migrations are immutable, so 139 and 152 are not edited. Each WHERE clause
-- below matches the exact text 116 left, so a tenant that has customised
-- either template through the notification CRUD API keeps its copy and is not
-- reworded by an upgrade - 139's own contract, inherited from 096. Re-running
-- is a no-op: the second run's WHERE misses because the copy has been
-- rewritten.

BEGIN;

-- auth.password_reset (email): migration 139's copy verbatim.
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
        || '</div></body></html>',
    updated_at = NOW()
WHERE event_type = 'auth.password_reset'
  AND channel_type = 'email'
  AND subject = 'Reset your {{app_name}} password'
  AND body_text = E'We received a request to reset your {{app_name}} password.\n\nUse the link below within 24 hours to set a new password.\n\n{{reset_link}}\n\nIf you did not request this, ignore this message.\n'
  AND body_html = '<!doctype html><html><body><p>We received a request to reset your {{app_name}} password.</p><p>Use the link below within 24 hours to set a new password.</p><p><a href="{{reset_link}}">{{reset_link}}</a></p><p>If you did not request this, ignore this message.</p></body></html>';

-- auth.welcome (email): migration 139's subject, and migration 152's bodies
-- (139's copy plus the client-portal paragraph 152 added).
UPDATE notification_templates SET
    subject = 'Welcome to {{msp_name}}',
    body_text = E'Hello {{display_name}},\n\n'
        || E'An account has been created for you at {{msp_name}}. '
        || E'Use the link below to set your password and finish signing in.\n\n'
        || E'{{setup_link}}\n\n'
        || E'{% if client_portal_url %}Once you are signed in you can invite your clients to their portal at:\n\n'
        || E'{{client_portal_url}}\n\n{% endif %}'
        || E'-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n',
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
        || '</div></body></html>',
    updated_at = NOW()
WHERE event_type = 'auth.welcome'
  AND channel_type = 'email'
  AND subject = 'Welcome to {{app_name}}'
  AND body_text = E'{{salutation}},\n\nAn account has been created for you in {{app_name}}. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n'
  AND body_html = '<!doctype html><html><body><p>{{salutation}},</p><p>An account has been created for you in {{app_name}}. Use the link below to set your password and finish signing in.</p><p><a href="{{setup_link}}">{{setup_link}}</a></p></body></html>';

COMMIT;
