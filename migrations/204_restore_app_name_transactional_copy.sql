-- PMS-1124 follow-up: undo migration 203. The copy migration 116 left is the
-- live contract for these two templates, and 203 replaced it with older text.
--
-- 203 was written on the premise that migration 139's branding "never landed
-- and should be restored". The premise was wrong, and the migration numbers
-- hide why. Ordered by when each was AUTHORED, not by its number:
--
--   139  PMS-729 phase 2 slice 5   2026-08-10   MSP branding, 'Hello {{display_name}},'
--   106  PMS-774                   2026-08-17   one shared '{{salutation}},' opener
--   116  PMS-789                   2026-08-26   product name -> '{{app_name}}'
--
-- 139 is the OLDEST of the three. It sat on the long-lived contact-login
-- branch and reached main on 2026-09-03 with a number that sorts after 106 and
-- 116, so its WHERE clauses no longer matched. That miss is what kept these two
-- templates consistent with the two decisions taken after it, and 203 undid
-- both of them: the welcome mail went back to 'Hello {{display_name}},', which
-- renders 'Hello ,' for a recipient whose name is unknown (the exact defect
-- PMS-774 fixed), and the password-reset mail stopped naming the deployment
-- the operator configured (PMS-789).
--
-- Four tests said so and are red on main: app_name_setting's
-- no_seeded_template_still_names_the_product_literally,
-- the_seeded_password_reset_mail_renders_the_configured_name and
-- the_seeded_password_reset_mail_is_unchanged_when_nothing_is_configured, plus
-- notifications' the_seeded_greetings_read_correctly_without_a_name.
--
-- Migrations are immutable, so 203 is not deleted; this restores what it
-- overwrote. Each WHERE matches 203's exact output, so a tenant that has edited
-- either template since keeps its copy, and re-running is a no-op.
--
-- This leaves notifications_branding::dispatch_injects_tenant_branding_into_render_context
-- red again, which is PMS-1124's original symptom. Whether a password-reset
-- mail names the product or the MSP is a product decision and is tracked there;
-- it is deliberately not decided by a migration.

BEGIN;

-- auth.password_reset (email): back to migration 116's copy.
UPDATE notification_templates SET
    subject = 'Reset your {{app_name}} password',
    body_text = E'We received a request to reset your {{app_name}} password.\n\nUse the link below within 24 hours to set a new password.\n\n{{reset_link}}\n\nIf you did not request this, ignore this message.\n',
    body_html = '<!doctype html><html><body><p>We received a request to reset your {{app_name}} password.</p><p>Use the link below within 24 hours to set a new password.</p><p><a href="{{reset_link}}">{{reset_link}}</a></p><p>If you did not request this, ignore this message.</p></body></html>',
    updated_at = NOW()
WHERE event_type = 'auth.password_reset'
  AND channel_type = 'email'
  AND subject = '{{msp_name}} - Reset your password'
  AND body_text = E'{{msp_name}} received a request to reset your password.\n\nUse the link below within 24 hours to set a new password.\n\n{{reset_link}}\n\nIf you did not request this, ignore this message.\n\n-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n';

-- auth.welcome (email): back to migration 116's copy, which is migration 106's
-- '{{salutation}},' opener with the product name templated.
UPDATE notification_templates SET
    subject = 'Welcome to {{app_name}}',
    body_text = E'{{salutation}},\n\nAn account has been created for you in {{app_name}}. Use the link below to set your password and finish signing in.\n\n{{setup_link}}\n',
    body_html = '<!doctype html><html><body><p>{{salutation}},</p><p>An account has been created for you in {{app_name}}. Use the link below to set your password and finish signing in.</p><p><a href="{{setup_link}}">{{setup_link}}</a></p></body></html>',
    updated_at = NOW()
WHERE event_type = 'auth.welcome'
  AND channel_type = 'email'
  AND subject = 'Welcome to {{msp_name}}'
  AND body_text = E'Hello {{display_name}},\n\n'
        || E'An account has been created for you at {{msp_name}}. '
        || E'Use the link below to set your password and finish signing in.\n\n'
        || E'{{setup_link}}\n\n'
        || E'{% if client_portal_url %}Once you are signed in you can invite your clients to their portal at:\n\n'
        || E'{{client_portal_url}}\n\n{% endif %}'
        || E'-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n';

COMMIT;
