-- Backfill the auth.portal_grant + auth.login_link notification templates +
-- rules into every pre-existing tenant that is missing them.
--
-- Background: migration 173_auth_portal_grant_template.sql seeded the
-- `auth.portal_grant` template + rule for the DEFAULT tenant
-- (00000000-0000-0000-0000-000000000001) only. `178_auth_login_link_template.sql`
-- did the same for `auth.login_link`. Every new tenant created after
-- MAPPS-501 (see `TenantService::seed_default_config`) gets both events copied
-- from the default tenant automatically; tenants created BEFORE that seeding
-- landed have no such rows.
--
-- The dispatcher iterates RULES (`NotificationsService::dispatch`), so an
-- event that has no rule for the caller's tenant silently drops the message:
-- `ContactService::grant_portal_access` mints the tokens and logs
-- "portal grant email queued", the dispatcher finds no rule, and the
-- recipient's mailbox stays empty. Same shape for the recurring sign-in
-- magic-link email fired by `/portal/login`'s finder page.
--
-- Backfill the exact same rows the new-tenant path produces
-- (`TenantService::seed_default_config`, the auth.portal_grant + auth.login_link
-- entries in its INSERT list). Mirrors migration 030's backfill for the SLA /
-- appointment-reminder templates, one MAPPS-501 event at a time.
--
-- Idempotency: both INSERTs are guarded with NOT EXISTS so a tenant that
-- already has a matching template / rule is untouched and re-running the
-- migration is a no-op. The default tenant itself is excluded from the target
-- set (it is the source).

DO $$
DECLARE
    default_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000001';
BEGIN
    -- 1. Copy the two templates into each tenant missing them. The NOT
    --    EXISTS guard keys on (tenant_id, event_type, channel_type) so a
    --    tenant that already has the template (e.g. one created via the
    --    new-tenant path, or a prior run of this migration) is skipped.
    INSERT INTO notification_templates
        (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
    SELECT t.id, src.name, src.event_type, src.channel_type,
           src.subject, src.body_text, src.body_html, src.is_active
    FROM tenants t
    CROSS JOIN notification_templates src
    WHERE src.tenant_id = default_tenant
      AND src.event_type IN ('auth.portal_grant', 'auth.login_link')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_templates existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = src.event_type
            AND existing.channel_type = src.channel_type
      );

    -- 2. Copy each default-tenant rule into each tenant missing it,
    --    re-linking template_id to that tenant's just-copied template
    --    by (event_type, channel_type) - the same join
    --    `TenantService::seed_default_config` uses, since the copied
    --    template has a fresh id. Recipients ride the dispatch context
    --    (`recipient_email` on the auth.portal_grant / auth.login_link
    --    dispatch call), so the recipients JSON is copied verbatim. The
    --    NOT EXISTS guard keys on (tenant_id, event_type, template_id)
    --    so a tenant that already has the rule is skipped, making
    --    re-runs a no-op.
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
      AND r.event_type IN ('auth.portal_grant', 'auth.login_link')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
            AND existing.template_id = nt.id
      );
END $$;
