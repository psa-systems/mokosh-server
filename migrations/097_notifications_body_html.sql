-- PMS-700: carry the authored HTML alternative through the dispatcher.
--
-- `notification_templates.body_html` has been authored since migration 013
-- (seeded by 021 / 023 / 028 / 096) but `dispatch` never wrote it into the
-- queue row and the worker had no column to read, so every dispatcher-
-- delivered message went out single-part plain text. The column below is
-- what dispatch renders into and the worker reads back for the
-- multipart/alternative send.
ALTER TABLE notifications ADD COLUMN body_html TEXT;

-- The transactional auth emails now have exactly one delivery path (the
-- dispatcher): the duplicate hard-coded bodies in `Mailer` are gone. Those
-- templates + rules were seeded for the default tenant only (migration 021),
-- and migration 030 deliberately skipped them because new tenants did not get
-- them either. With no direct-send fallback left, a tenant missing the rows
-- would get no password-reset or welcome mail at all, so seed them everywhere.
-- `TenantService::copy_default_config` copies the same event types for tenants
-- created from here on.
--
-- Idempotency: both INSERTs are guarded with NOT EXISTS, keyed the same way as
-- migration 030, so a tenant that already has the rows is untouched and a
-- re-run is a no-op. The default tenant is excluded (it is the source).
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
      AND src.event_type IN ('auth.password_reset', 'auth.welcome')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_templates existing
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
      AND r.event_type IN ('auth.password_reset', 'auth.welcome')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
            AND existing.template_id = nt.id
      );
END $$;
