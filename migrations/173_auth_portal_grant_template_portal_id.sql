-- PMS-928 (mokosh-contact-login prompt 011): fold the new Portal ID
-- into the `auth.portal_grant` email seeded by migration 144.
--
-- Migration 144's body only rendered the magic-link URL + set-password
-- URL. Prompt 011's grant flow assigns a 9-digit numeric Portal ID at
-- grant time and the email must surface it prominently so the
-- recipient can:
--   - Dictate it over the phone (the whole point of the numeric shape).
--   - Type it into the generic `/portal/login` page on a device that
--     lost its bookmark.
--   - Recognise their own Portal ID when it appears in support tickets
--     or in the AWS-IAM-style three-field sign-in prompt (Portal ID +
--     email + password).
--
-- New placeholder in the render context (populated by
-- `ContactService::send_grant_email`):
--   `portal_id` -> the 9-digit numeric id (rendered as a string so the
--                  flat `{{key}}` replacer in
--                  `notifications::render_template` inserts it verbatim
--                  without integer-formatting surprises).
--
-- Migration 144 stays immutable; this migration UPDATEs the seeded row
-- in place so the template picks up the new placeholder without a
-- new event_type / rule pair.

UPDATE notification_templates
   SET body_text =
           E'Hello {{display_name}},\n\n'
        || E'You have been granted access to your {{msp_name}} client portal.\n\n'
        || E'Your Portal ID: {{portal_id}}\n\n'
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
        || '<strong>Your Portal ID:</strong> <span style="font-family:monospace;font-size:17px;letter-spacing:1px;">{{portal_id}}</span>'
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
