-- PMS-1140: the two transactional mails that serve two audiences from one
-- template get a portal-side event of their own.
--
-- The question PMS-1124 left open was whether the password-reset and welcome
-- mail name the product or the MSP. Neither, as one template: they are two
-- mails to two audiences, and the codebase already answers this. Every
-- template that serves ONLY a portal contact names the MSP
-- ('Sign in to your {{msp_name}} portal', migrations 173 and 178), and 173's
-- own header states the rule: "A dedicated event type (rather than folding
-- the second link into `auth.welcome`) keeps this concern separate from the
-- staff-side MSP-admin welcome email that also uses `auth.welcome`."
--
-- `notifications::render_template` is a flat `{{key}}` replacer with no
-- conditionals, so one template cannot serve two audiences without leaking:
-- an unsupplied key is emitted verbatim into the recipient's inbox. Migration
-- 152 tried to bridge that with `{% if client_portal_url %}` and would have
-- shipped a literal `{% if %}` had its guard matched. Splitting removes the
-- need for a conditional rather than adding one to the renderer.
--
-- Three defects this closes, each observed rather than inferred:
--
--   1. `ContactPortalService::request_password_reset` dispatches
--      `auth.password_reset`, whose copy is migration 116's
--      'Reset your {{app_name}} password'. The recipient is a `contacts` row,
--      the MSP's customer, so every portal password reset names the product
--      the customer has never heard of instead of the MSP they hired.
--   2. `TenantService::send_admin_welcome` supplies `display_name` and the
--      `auth.welcome` template opens with `{{salutation}}` (migration 106),
--      which nothing on that path supplies, so that mail goes out with a
--      literal `{{salutation}},` on its first line.
--   3. That same path computes `client_portal_url` and no template has
--      referenced it since migration 152 matched zero rows, so the admin is
--      never told where their portal is.
--
-- `auth.password_reset` and `auth.welcome` are NOT touched. After this they
-- serve staff only, so migration 116's `{{app_name}}` is right for both and
-- PMS-789's decision stands unchanged; migration 204's four tests stay green.
--
-- Seeded for the default tenant (the pattern of migration 021), backfilled
-- into every existing tenant, and added to the copy lists in
-- `TenantService::seed_default_config` so a new tenant gets both. A template
-- with no rule is a message that is never sent (PMS-761), so each gets both.

BEGIN;

-- ============================================================================
-- 1. auth.portal_password_reset: a customer resetting their portal password.
--
-- Context from `ContactPortalService::request_password_reset`:
--   {{reset_link}}   the /portal/{slug}/reset-password link, 24 hours
--   msp_* injected by `NotificationsService::dispatch`
-- ============================================================================

INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Portal Password Reset - Email',
     'auth.portal_password_reset',
     'email',
     'Reset your {{msp_name}} portal password',
     E'We received a request to reset your password for the {{msp_name}} client portal.\n\n'
        || E'Use the link below within 24 hours to set a new password.\n\n'
        || E'{{reset_link}}\n\n'
        || E'If you did not request this, ignore this message.\n\n'
        || E'-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n',
     E'<!doctype html><html><body style="font-family:sans-serif;color:#111;margin:0;padding:0;">'
        || '<div style="max-width:560px;margin:0 auto;padding:24px;">'
        || '<div style="border-bottom:3px solid {{msp_primary_color}};padding-bottom:12px;margin-bottom:16px;">'
        || '<img src="{{msp_logo_url}}" alt="{{msp_name}}" style="max-height:48px;">'
        || '</div>'
        || '<h1 style="font-size:18px;margin:0 0 12px 0;">Reset your password</h1>'
        || '<p>We received a request to reset your password for the {{msp_name}} client portal.</p>'
        || '<p>Use the button below within 24 hours to set a new password.</p>'
        || '<p><a href="{{reset_link}}" style="display:inline-block;background:{{msp_primary_color}};color:#fff;padding:10px 16px;border-radius:4px;text-decoration:none;">Set a new password</a></p>'
        || '<p style="color:#666;font-size:12px;">If the button does not work, paste this link into your browser:<br><a href="{{reset_link}}">{{reset_link}}</a></p>'
        || '<p style="color:#666;font-size:12px;">If you did not request this, ignore this message.</p>'
        || '<hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px 0;">'
        || '<p style="color:#666;font-size:12px;">Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.</p>'
        || '</div></body></html>',
     TRUE);

-- ============================================================================
-- 2. auth.portal_welcome: the MSP admin of a freshly provisioned tenant.
--
-- The recipient is the MSP's own admin, not a client, so this one keeps
-- `{{app_name}}`: they are being onboarded onto the product, and the portal
-- URL is where they will later invite their clients. What it fixes is the two
-- defects above - it opens with `{{salutation}}`, which the dispatch site now
-- supplies, and it names `{{client_portal_url}}` unconditionally, which is
-- safe here because this template has exactly one dispatch site.
--
-- Context from `TenantService::send_admin_welcome`:
--   {{salutation}}         'Hello Ada', or 'Hello' when no name is on file
--   {{setup_link}}         /portal/set-password?token=...
--   {{client_portal_url}}  the portal origin this deployment serves
-- ============================================================================

INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Portal Admin Welcome - Email',
     'auth.portal_welcome',
     'email',
     'Welcome to {{app_name}}',
     E'{{salutation}},\n\n'
        || E'An account has been created for you in {{app_name}}. Use the link below to set your password and finish signing in.\n\n'
        || E'{{setup_link}}\n\n'
        || E'Once you are signed in you can invite your clients to their portal at:\n\n'
        || E'{{client_portal_url}}\n',
     '<!doctype html><html><body><p>{{salutation}},</p>'
        || '<p>An account has been created for you in {{app_name}}. Use the link below to set your password and finish signing in.</p>'
        || '<p><a href="{{setup_link}}">{{setup_link}}</a></p>'
        || '<p>Once you are signed in you can invite your clients to their portal at <a href="{{client_portal_url}}">{{client_portal_url}}</a>.</p>'
        || '</body></html>',
     TRUE);

-- ============================================================================
-- 3. Rules for both. Recipients ride the dispatch context's
--    `recipient_email`, the shape every auth.* rule uses.
-- ============================================================================

INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    CASE t.event_type
        WHEN 'auth.portal_password_reset' THEN 'Default - Portal Password Reset - Email'
        ELSE 'Default - Portal Admin Welcome - Email'
    END,
    t.event_type,
    ARRAY['email']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type IN ('auth.portal_password_reset', 'auth.portal_welcome')
  AND t.channel_type = 'email';

-- ============================================================================
-- 4. Backfill every tenant that already exists, the shape of migration 202.
--    Without this, switching the dispatch sites over would silently stop the
--    mail for every tenant provisioned before today: `dispatch` iterates
--    RULES, and a tenant with none for an event sends nothing and says
--    nothing.
-- ============================================================================

DO $$
DECLARE
    default_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000001';
BEGIN
    INSERT INTO notification_templates
        (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
    SELECT t.id, src.name, src.event_type, src.channel_type,
           src.subject, src.body_text, src.body_html, src.is_active
    FROM tenants t
    CROSS JOIN notification_templates src
    WHERE src.tenant_id = default_tenant
      AND src.event_type IN ('auth.portal_password_reset', 'auth.portal_welcome')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1 FROM notification_templates existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = src.event_type
            AND existing.channel_type = src.channel_type
      );

    INSERT INTO notification_rules
        (tenant_id, name, event_type, channels, recipients, template_id, is_active)
    SELECT t.id, r.name, r.event_type, r.channels, r.recipients, nt.id, r.is_active
    FROM tenants t
    CROSS JOIN notification_rules r
    JOIN notification_templates ot
      ON ot.id = r.template_id AND ot.tenant_id = default_tenant
    JOIN notification_templates nt
      ON nt.tenant_id = t.id
     AND nt.event_type = ot.event_type
     AND nt.channel_type = ot.channel_type
    WHERE r.tenant_id = default_tenant
      AND r.event_type IN ('auth.portal_password_reset', 'auth.portal_welcome')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1 FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
      );
END $$;

COMMIT;
