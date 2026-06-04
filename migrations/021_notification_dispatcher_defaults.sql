-- Default notification templates + rules for the transactional events
-- the auth and tickets modules dispatch through NotificationsService.
--
-- Each event_type below is sent on behalf of a specific user, so the
-- rule's recipients column stays empty; the dispatcher merges the
-- caller-provided context.recipient_email / context.recipient_user_id
-- into fanout at send time. Bodies use {{key}} placeholders that the
-- dispatcher resolves from the context JSON. E'...' string literals so
-- \n is interpreted as a real newline at insert time.

INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html)
VALUES
    -- auth.password_reset
    ('00000000-0000-0000-0000-000000000001',
     'Password Reset - Email',
     'auth.password_reset',
     'email',
     'Reset your Mokosh password',
     E'We received a request to reset your Mokosh password.\n\nUse the link below within 24 hours to set a new password.\n\n{{reset_link}}\n\nIf you did not request this, ignore this message.\n',
     '<!doctype html><html><body><p>We received a request to reset your Mokosh password.</p><p>Use the link below within 24 hours to set a new password.</p><p><a href="{{reset_link}}">{{reset_link}}</a></p><p>If you did not request this, ignore this message.</p></body></html>'),

    -- auth.welcome
    ('00000000-0000-0000-0000-000000000001',
     'Welcome - Email',
     'auth.welcome',
     'email',
     'Welcome to Mokosh',
     E'Hello {{display_name}},\n\nAn account has been created for you in Mokosh. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n',
     '<!doctype html><html><body><p>Hello {{display_name}},</p><p>An account has been created for you in Mokosh. Use the link below to set your password and finish signing in.</p><p><a href="{{setup_link}}">{{setup_link}}</a></p></body></html>'),

    -- ticket.note_added
    ('00000000-0000-0000-0000-000000000001',
     'Ticket Note Added - Email',
     'ticket.note_added',
     'email',
     '[{{ticket_number}}] {{ticket_title}}',
     E'A new update has been added to ticket {{ticket_number}}:\n\n{{content}}\n',
     NULL),

    -- ticket.automation.notify
    ('00000000-0000-0000-0000-000000000001',
     'Ticket Automation Notify - Email',
     'ticket.automation.notify',
     'email',
     '{{subject}}',
     '{{body}}',
     NULL);

-- One rule per event_type, channel=email, recipients are sourced from
-- the dispatch context. template_id is resolved via a subquery so we do
-- not need to know the generated UUIDs in this migration.

INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - ' || t.name,
    t.event_type,
    ARRAY['email']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type IN ('auth.password_reset', 'auth.welcome', 'ticket.note_added', 'ticket.automation.notify')
  AND t.channel_type = 'email';
