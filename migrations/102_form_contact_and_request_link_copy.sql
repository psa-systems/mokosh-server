-- PMS-748: say who sent a request form, who it was meant for, and how to ask.
--
-- Two changes that only make sense together: a place for a form to carry the
-- MSP's contact details, and the email copy that uses them.
--
-- ============================================================================
-- 1. PER-FORM CONTACT DETAILS
-- ============================================================================
--
-- Free text rather than structured email/phone columns. What a client should
-- be told to do varies ("call the service desk on 555-0100", "reply to your
-- account manager"), and the value is rendered as a sentence on the form page
-- and in the email rather than parsed. Optional: the MSP NAME is always shown,
-- the contact line only when a definition carries one.
--
-- Per definition rather than per tenant because different request types route
-- to different desks. A tenant-level default a form can override is the
-- obvious follow-up and is deliberately not built here.

ALTER TABLE form_definitions
    ADD COLUMN IF NOT EXISTS contact_info VARCHAR(200);

-- ============================================================================
-- 2. REQUEST-LINK EMAIL COPY
-- ============================================================================
--
-- Migration 101 seeded this template for every tenant. Migrations are
-- immutable once applied, so the copy is replaced here rather than edited
-- there.
--
-- The WHERE clause matches the seeded body verbatim. A tenant that has since
-- customised its own template through the notification CRUD API keeps its
-- copy: this migration rewrites only rows still holding exactly what 101 put
-- in them. Migration 101's INSERT took the same care in the other direction.
--
-- New placeholders (`sender_name`, `company_name`, `contact_line`,
-- `abuse_notice`, `abuse_notice_html`) are supplied on every send by
-- `FormsService::queue_request_link_email`. An unsupplied key renders its own
-- braces to the client (`render_template`), which was the MAPPS-425 defect, so
-- none of these is conditional server-side: every one is always present, and
-- the two that can be empty are empty STRINGS rather than absent keys.
--
-- `abuse_notice_html` carries its own `<p>` wrapper. `render_template` has no
-- conditionals, so a wrapper in the template would leave an empty paragraph on
-- every deployment that has not configured an abuse address. Composing the
-- whole element server-side is what lets the line disappear completely.

UPDATE notification_templates
SET subject = '{{form_name}} request form from {{tenant_name}}',
    body_text = E'{{display_name}},\n\n{{sender_name}} at {{tenant_name}} has sent you the {{form_name}} request form. Please open the link below and fill in the requested information:\n\n{{form_link}}\n\nThis link is for your use only, can be submitted once, and expires on {{expires_on}}.\n\n{{contact_line}}\n\nThis email was sent by {{tenant_name}} and was intended for {{company_name}}.{{abuse_notice}}',
    body_html = '<p>{{display_name}},</p><p><strong>{{sender_name}}</strong> at {{tenant_name}} has sent you the <strong>{{form_name}}</strong> request form. Please open it and fill in the requested information.</p><p><a href="{{form_link}}">Open the {{form_name}} request form</a></p><p>This link is for your use only, can be submitted once, and expires on {{expires_on}}.</p><p>{{contact_line}}</p><p>This email was sent by {{tenant_name}} and was intended for {{company_name}}.</p>{{abuse_notice_html}}',
    updated_at = NOW()
WHERE event_type = 'forms.request_link'
  AND channel_type = 'email'
  AND body_text = E'{{display_name}},\n\nPlease complete the {{form_name}} form so we can action your request:\n\n{{form_link}}\n\nThis link is for your use only, can be submitted once, and expires on {{expires_on}}.\n\nIf you were not expecting this, you can ignore this message.'
  AND body_html = '<p>{{display_name}},</p><p>Please complete the <strong>{{form_name}}</strong> form so we can action your request.</p><p><a href="{{form_link}}">Open the {{form_name}} form</a></p><p>This link is for your use only, can be submitted once, and expires on {{expires_on}}.</p><p>If you were not expecting this, you can ignore this message.</p>';
