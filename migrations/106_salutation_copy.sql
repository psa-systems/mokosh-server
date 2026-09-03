-- PMS-774: one salutation for every transactional message.
--
-- Two templates opened two different ways. `forms.request_link` put no
-- greeting word in the template at all and relied on the composer passing the
-- WORD "Hello" as the name when there was no contact, so a link to a bare
-- address opened "Hello," and a link to a known contact opened "David,".
-- `auth.welcome` put the greeting in the template ("Hello {{display_name}},")
-- and rendered "Hello ," for a user created with no names, because the
-- composer supplies an empty string there.
--
-- Both now take `{{salutation}}`, composed by `utils::email::salutation`,
-- which yields "Hello David" or "Hello" and never a trailing space. The comma
-- stays in the template, so it lands directly after either form. The composers
-- still supply `display_name` as the bare name: `render_template` has no
-- conditionals and renders an unsupplied key as literal braces to the client
-- (the MAPPS-425 defect), so a tenant holding a CUSTOMISED template that still
-- names `{{display_name}}` keeps rendering.
--
-- Migrations are immutable once applied (021, 101, 102 and 103 seeded and
-- rewrote these rows), so this is a new file rather than an edit to any of
-- them. Each WHERE clause matches the current seeded body verbatim, exactly as
-- 102 and 103 do, so a tenant that has customised its own copy through the
-- notification CRUD API is left alone.

-- ============================================================================
-- 1. forms.request_link  (body_text from 102, body_html from 103)
-- ============================================================================

UPDATE notification_templates
SET body_text = E'{{salutation}},\n\n{{sender_name}} at {{tenant_name}} has sent you the {{form_name}} request form. Please open the link below and fill in the requested information:\n\n{{form_link}}\n\nThis link is for your use only, can be submitted once, and expires on {{expires_on}}.\n\n{{contact_line}}\n\nThis email was sent by {{tenant_name}} and was intended for {{company_name}}.{{abuse_notice}}',
    body_html = '{{logo_html}}<p>{{salutation}},</p><p><strong>{{sender_name}}</strong> at {{tenant_name}} has sent you the <strong>{{form_name}}</strong> request form. Please open it and fill in the requested information.</p><p><a href="{{form_link}}">Open the {{form_name}} request form</a></p><p>This link is for your use only, can be submitted once, and expires on {{expires_on}}.</p><p>{{contact_line}}</p><p>This email was sent by {{tenant_name}} and was intended for {{company_name}}.</p>{{abuse_notice_html}}',
    updated_at = NOW()
WHERE event_type = 'forms.request_link'
  AND channel_type = 'email'
  AND body_text = E'{{display_name}},\n\n{{sender_name}} at {{tenant_name}} has sent you the {{form_name}} request form. Please open the link below and fill in the requested information:\n\n{{form_link}}\n\nThis link is for your use only, can be submitted once, and expires on {{expires_on}}.\n\n{{contact_line}}\n\nThis email was sent by {{tenant_name}} and was intended for {{company_name}}.{{abuse_notice}}'
  AND body_html = '{{logo_html}}<p>{{display_name}},</p><p><strong>{{sender_name}}</strong> at {{tenant_name}} has sent you the <strong>{{form_name}}</strong> request form. Please open it and fill in the requested information.</p><p><a href="{{form_link}}">Open the {{form_name}} request form</a></p><p>This link is for your use only, can be submitted once, and expires on {{expires_on}}.</p><p>{{contact_line}}</p><p>This email was sent by {{tenant_name}} and was intended for {{company_name}}.</p>{{abuse_notice_html}}';

-- ============================================================================
-- 2. auth.welcome  (seeded by 021, copied to every tenant by 097)
-- ============================================================================

UPDATE notification_templates
SET body_text = E'{{salutation}},\n\nAn account has been created for you in Mokosh. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n',
    body_html = '<!doctype html><html><body><p>{{salutation}},</p><p>An account has been created for you in Mokosh. Use the link below to set your password and finish signing in.</p><p><a href="{{setup_link}}">{{setup_link}}</a></p></body></html>',
    updated_at = NOW()
WHERE event_type = 'auth.welcome'
  AND channel_type = 'email'
  AND body_text = E'Hello {{display_name}},\n\nAn account has been created for you in Mokosh. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n'
  AND body_html = '<!doctype html><html><body><p>Hello {{display_name}},</p><p>An account has been created for you in Mokosh. Use the link below to set your password and finish signing in.</p><p><a href="{{setup_link}}">{{setup_link}}</a></p></body></html>';
