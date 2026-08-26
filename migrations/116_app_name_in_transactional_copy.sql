-- PMS-789: the two transactional templates that name the product read the
-- deployment's app-name setting instead of the literal "Mokosh".
--
-- `auth.password_reset` and `auth.welcome` are the only seeded templates whose
-- copy names the product (verified against a migrated database, not inferred
-- from the seed files: 021 seeded both, 096/097 reseeded and added the HTML
-- alternative, 106 rewrote the welcome bodies for {{salutation}}). Without this
-- an operator who sets the app name to "PSA Systems" still sends password
-- resets that say "Reset your Mokosh password", which is the exact mismatch
-- PMS-789 exists to remove.
--
-- `{{app_name}}` is supplied by `NotificationsService::render_event` for every
-- template on every dispatch and preview, so it can never render as literal
-- braces the way an unsupplied key does.
--
-- Migrations are immutable once applied, so this is a new file rather than an
-- edit to 021 or 106. Each WHERE clause matches the current stored copy
-- verbatim, exactly as 102, 103 and 106 do, so a tenant that has customised its
-- own copy through the notification CRUD API keeps it and is not silently
-- reworded by an upgrade.

-- ============================================================================
-- 1. auth.password_reset  (subject + bodies seeded by 021, HTML by 097)
-- ============================================================================

UPDATE notification_templates
SET subject = 'Reset your {{app_name}} password',
    body_text = E'We received a request to reset your {{app_name}} password.\n\nUse the link below within 24 hours to set a new password.\n\n{{reset_link}}\n\nIf you did not request this, ignore this message.\n',
    body_html = '<!doctype html><html><body><p>We received a request to reset your {{app_name}} password.</p><p>Use the link below within 24 hours to set a new password.</p><p><a href="{{reset_link}}">{{reset_link}}</a></p><p>If you did not request this, ignore this message.</p></body></html>',
    updated_at = NOW()
WHERE event_type = 'auth.password_reset'
  AND channel_type = 'email'
  AND subject = 'Reset your Mokosh password'
  AND body_text = E'We received a request to reset your Mokosh password.\n\nUse the link below within 24 hours to set a new password.\n\n{{reset_link}}\n\nIf you did not request this, ignore this message.\n'
  AND body_html = '<!doctype html><html><body><p>We received a request to reset your Mokosh password.</p><p>Use the link below within 24 hours to set a new password.</p><p><a href="{{reset_link}}">{{reset_link}}</a></p><p>If you did not request this, ignore this message.</p></body></html>';

-- ============================================================================
-- 2. auth.welcome  (subject from 021, bodies as 106 left them)
-- ============================================================================

UPDATE notification_templates
SET subject = 'Welcome to {{app_name}}',
    body_text = E'{{salutation}},\n\nAn account has been created for you in {{app_name}}. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n',
    body_html = '<!doctype html><html><body><p>{{salutation}},</p><p>An account has been created for you in {{app_name}}. Use the link below to set your password and finish signing in.</p><p><a href="{{setup_link}}">{{setup_link}}</a></p></body></html>',
    updated_at = NOW()
WHERE event_type = 'auth.welcome'
  AND channel_type = 'email'
  AND subject = 'Welcome to Mokosh'
  AND body_text = E'{{salutation}},\n\nAn account has been created for you in Mokosh. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n'
  AND body_html = '<!doctype html><html><body><p>{{salutation}},</p><p>An account has been created for you in Mokosh. Use the link below to set your password and finish signing in.</p><p><a href="{{setup_link}}">{{setup_link}}</a></p></body></html>';
