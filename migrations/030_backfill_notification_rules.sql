-- Backfill the default worker notification templates + rules into every
-- pre-existing tenant that is missing them.
--
-- Background: new tenants get these rows from
-- TenantService::copy_default_config (src/modules/tenants/service.rs,
-- lines 458-502), which copies the default tenant's in-app worker
-- templates + rules for event_type ('appointment.reminder',
-- 'sla.at_risk', 'sla.breached') and re-links each copied rule's
-- template_id to the copied template by (event_type, channel_type).
-- Tenants created BEFORE that seeding landed have no such rows, so the
-- SLA sweep (027) and appointment-reminder (028) workers find no active
-- rule for them and never auto-deliver. This migration backfills the
-- exact same rows the new-tenant path produces.
--
-- Canonical source: the default tenant
-- (00000000-0000-0000-0000-000000000001) rows seeded by migrations 027
-- and 028. We deliberately scope to the SAME three worker event types
-- copy_default_config copies. The transactional auth.* / ticket.* email
-- templates from migration 021 are intentionally NOT backfilled here,
-- because new tenants do not get them either (per the comment at
-- service.rs:458-463 they stay on the default-tenant migration seed and
-- per-tenant CRUD); backfilling them would make existing tenants diverge
-- from new ones.
--
-- Idempotency: both INSERTs are guarded with NOT EXISTS so a tenant that
-- already has a matching template / rule is untouched and re-running the
-- migration is a no-op (no duplicates). The default tenant itself is
-- excluded from the target set (it is the source).

DO $$
DECLARE
    default_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000001';
BEGIN
    -- 1. Copy the three worker templates into each tenant missing them,
    --    matching copy_default_config's template copy exactly (same
    --    columns, same event_type filter). The NOT EXISTS guard keys on
    --    (tenant_id, event_type, channel_type) so a tenant that already
    --    has the template (e.g. a tenant created via the new-tenant path,
    --    or a prior run of this migration) is skipped.
    INSERT INTO notification_templates
        (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
    SELECT t.id, src.name, src.event_type, src.channel_type,
           src.subject, src.body_text, src.body_html, src.is_active
    FROM tenants t
    CROSS JOIN notification_templates src
    WHERE src.tenant_id = default_tenant
      AND src.event_type IN ('appointment.reminder', 'sla.at_risk', 'sla.breached')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_templates existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = src.event_type
            AND existing.channel_type = src.channel_type
      );

    -- 2. Copy each default-tenant rule into each tenant missing it,
    --    re-linking template_id to that tenant's just-copied template by
    --    (event_type, channel_type) - the same join
    --    copy_default_config uses, since the copied template has a fresh
    --    id. Recipients ride the dispatch context (the workers pass the
    --    assignee via context.recipient_user_id), so the recipients JSON
    --    is copied verbatim ('{"user_ids": [], "emails": []}'). The NOT
    --    EXISTS guard keys on (tenant_id, event_type, template_id) so a
    --    tenant that already has the rule is skipped, making re-runs a
    --    no-op.
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
      AND r.event_type IN ('appointment.reminder', 'sla.at_risk', 'sla.breached')
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1
          FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
            AND existing.template_id = nt.id
      );
END $$;
