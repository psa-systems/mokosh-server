-- MAPPS-429: put the tenant's logo at the top of the request-form email.
--
-- Third rewrite of the same seeded row: 101 created it, 102 (PMS-748) replaced
-- the copy, this adds one placeholder. Migrations are immutable once applied,
-- so each is a new file rather than an edit to the last.
--
-- The WHERE clause matches the PMS-748 body verbatim, so a tenant that has
-- customised its own template through the notification CRUD API keeps it, and a
-- tenant still holding the ORIGINAL 101 copy is left alone too: it has no logo
-- placeholder and does not gain one, which is correct, because nothing about
-- this migration should quietly redesign a message an operator wrote.
--
-- `{{logo_html}}` is composed server-side into either a complete `<p><img></p>`
-- or an empty string (`FormsService::queue_request_link_email`). `render_template`
-- has no conditionals, so an element that must sometimes disappear cannot be
-- written into the template, and a key that is sometimes absent renders literal
-- braces to the client, which was the MAPPS-425 defect. It is therefore always
-- supplied, and empty when the deployment has no `PUBLIC_API_BASE_URL` or the
-- tenant has no logo.
--
-- Text bodies get nothing: a plain-text part cannot show an image, and a bare
-- URL to one is noise.

UPDATE notification_templates
SET body_html = '{{logo_html}}<p>{{display_name}},</p><p><strong>{{sender_name}}</strong> at {{tenant_name}} has sent you the <strong>{{form_name}}</strong> request form. Please open it and fill in the requested information.</p><p><a href="{{form_link}}">Open the {{form_name}} request form</a></p><p>This link is for your use only, can be submitted once, and expires on {{expires_on}}.</p><p>{{contact_line}}</p><p>This email was sent by {{tenant_name}} and was intended for {{company_name}}.</p>{{abuse_notice_html}}',
    updated_at = NOW()
WHERE event_type = 'forms.request_link'
  AND channel_type = 'email'
  AND body_html = '<p>{{display_name}},</p><p><strong>{{sender_name}}</strong> at {{tenant_name}} has sent you the <strong>{{form_name}}</strong> request form. Please open it and fill in the requested information.</p><p><a href="{{form_link}}">Open the {{form_name}} request form</a></p><p>This link is for your use only, can be submitted once, and expires on {{expires_on}}.</p><p>{{contact_line}}</p><p>This email was sent by {{tenant_name}} and was intended for {{company_name}}.</p>{{abuse_notice_html}}';
