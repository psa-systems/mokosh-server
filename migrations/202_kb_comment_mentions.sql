-- PMS-1129: an @mention in a KB comment notifies the person once.
--
-- `kb_comment_mentions` is the once-only guard: one row per (comment, user),
-- written when a comment is created or edited and the body names the user,
-- and the dispatch happens only for a row this write INSERTED. An edit that
-- adds a handle notifies that person; a re-save of the same text inserts
-- nothing and notifies nobody; the author naming themselves is recorded and
-- never notified (that is decided in the service, so the row still says the
-- author was named). `tenant_id` is carried for the ordinary RLS policy.
--
-- The `kb.comment.mention` in-app template and rule are seeded for the
-- default tenant, the pattern of migration 021, and backfilled into every
-- other tenant the way migration 186 did, because `dispatch` iterates RULES
-- and a tenant with no rule for the event queues nothing. New tenants get
-- both copied by `TenantService::seed_default_config`.

CREATE TABLE kb_comment_mentions (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    comment_id UUID NOT NULL REFERENCES kb_article_comments(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    notified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (comment_id, user_id)
);

ALTER TABLE kb_comment_mentions ENABLE ROW LEVEL SECURITY;
ALTER TABLE kb_comment_mentions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON kb_comment_mentions;
CREATE POLICY tenant_isolation ON kb_comment_mentions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- The in-app template for the default tenant. The bell shows subject and
-- body; the row's entity_type / entity_id carry the deep link.
INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'KB Comment Mention - In-App',
     'kb.comment.mention',
     'in_app',
     '{{author_name}} mentioned you on {{article_title}}',
     E'{{author_name}} mentioned you in a comment on "{{article_title}}":\n\n{{excerpt}}\n',
     NULL);

INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - ' || t.name,
    t.event_type,
    ARRAY['in_app']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type = 'kb.comment.mention'
  AND t.channel_type = 'in_app';

-- Every other tenant, the migration 186 shape, idempotent on re-run.
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
      AND src.event_type = 'kb.comment.mention'
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
      AND r.event_type = 'kb.comment.mention'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1 FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
            AND existing.template_id = nt.id
      );
END $$;
