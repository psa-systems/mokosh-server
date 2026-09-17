-- PMS-1215 (PSA-70 phase 5): import runs a closed browser tab cannot abort,
-- and a failing connection that says so without anyone reading logs.

BEGIN;

-- ============================================================================
-- 1. contact_sync_runs
-- ============================================================================
--
-- The `portal_exports` shape (migration 144): a request inserts a row, a
-- worker drains it, and the row is what a client polls. The request never
-- waits on the import, so nothing the browser does can stop it.
--
-- RESUMING IS REPLAYING. A run interrupted by a restart is found by its stale
-- heartbeat and put back in the queue, and starts over from the connection's
-- `sync_token`, which the sync only advances once every record has landed
-- (PMS-1213). The records it already applied replay as no-ops against their
-- stored etags, so the cursor a run resumes from is that token rather than a
-- page position here: a page token is only valid inside the one read that
-- issued it, and a resume after a restart is not that read.
CREATE TABLE contact_sync_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES contact_sync_connections(id) ON DELETE CASCADE,
    -- `initial` is the first import after a label selection, `manual` a
    -- person pressing Sync now, `scheduled` the worker's interval.
    trigger VARCHAR(16) NOT NULL CHECK (trigger IN ('initial', 'manual', 'scheduled')),
    status VARCHAR(16) NOT NULL DEFAULT 'queued' CHECK (
        status IN ('queued', 'running', 'completed', 'failed', 'cancelled')
    ),
    requested_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    -- A rate-limited run goes back to `queued` with this set, rather than to
    -- `failed`: being asked to wait is not a failure (PSA-70 I).
    not_before TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    -- The sync token the run read from. NULL is a full read.
    cursor TEXT,
    full_read BOOLEAN,
    -- What landed. `processed` against `total` is the progress bar.
    total INTEGER,
    processed INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL DEFAULT 0,
    linked INTEGER NOT NULL DEFAULT 0,
    updated INTEGER NOT NULL DEFAULT 0,
    queued_for_review INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0,
    deleted_in_source INTEGER NOT NULL DEFAULT 0,
    -- What did not, per record: `[{"external_id", "reason"}]`, capped by the
    -- writer so one broken import cannot grow a row without bound.
    failed_records INTEGER NOT NULL DEFAULT 0,
    failures JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Why the run as a whole stopped, in this codebase's words.
    error TEXT,
    cancel_requested_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One active run per connection: a second Sync now while one is queued or
-- running is a 409, not a second import racing the first.
CREATE UNIQUE INDEX idx_contact_sync_runs_active
    ON contact_sync_runs (connection_id)
    WHERE status IN ('queued', 'running');

CREATE INDEX idx_contact_sync_runs_recent
    ON contact_sync_runs (tenant_id, connection_id, created_at DESC);

CREATE INDEX idx_contact_sync_runs_claimable
    ON contact_sync_runs (created_at)
    WHERE status = 'queued';

ALTER TABLE contact_sync_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_sync_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_sync_runs
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- 2. Repeated failure, counted where the Settings card reads it
-- ============================================================================
--
-- One failed run is weather; several in a row is a broken integration somebody
-- has to hear about. `failure_notified_at` makes the notification once per
-- streak rather than once per interval, and a success clears both.
ALTER TABLE contact_sync_connections
    ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN failure_notified_at TIMESTAMPTZ;

-- ============================================================================
-- 3. contact_sync.failing: its own event (PMS-1140), seeded, ruled, backfilled
-- ============================================================================
--
-- Staff-facing, so it names the product the way every staff mail does.
-- Context supplied by `ContactSyncRunner::record_outcome`:
--   {{salutation}}      'Hello Ada', or 'Hello'
--   {{account_email}}   the connected Google account
--   {{failure_count}}   consecutive failed syncs, as digits
--   {{last_error}}      what the last one said, in this codebase's words
--   {{settings_url}}    where the connection is managed
INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Contact Sync Failing - Email',
     'contact_sync.failing',
     'email',
     'Google Contacts import is failing for {{account_email}}',
     E'{{salutation}},\n\n'
        || E'The Google Contacts import for {{account_email}} has not completed {{failure_count}} times in a row.\n\n'
        || E'The last attempt said: {{last_error}}\n\n'
        || E'Nothing has been deleted, and contacts already imported are unchanged. Open the integration in {{app_name}} to see what happened:\n\n'
        || E'{{settings_url}}\n',
     '<!doctype html><html><body>'
        || '<p>{{salutation}},</p>'
        || '<p>The Google Contacts import for <strong>{{account_email}}</strong> has not completed {{failure_count}} times in a row.</p>'
        || '<p>The last attempt said: {{last_error}}</p>'
        || '<p>Nothing has been deleted, and contacts already imported are unchanged.</p>'
        || '<p><a href="{{settings_url}}">Open the integration in {{app_name}}</a></p>'
        || '</body></html>',
     TRUE);

-- Recipients ride the dispatch context: the admin who connected the account,
-- else the tenant's longest-standing active admin. A tenant adds anyone else
-- in its notification settings.
INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default - Contact Sync Failing - Email',
    t.event_type,
    ARRAY['email']::VARCHAR(20)[],
    '{"user_ids": [], "emails": []}'::jsonb,
    t.id,
    TRUE
FROM notification_templates t
WHERE t.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND t.event_type = 'contact_sync.failing'
  AND t.channel_type = 'email';

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
      AND src.event_type = 'contact_sync.failing'
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
      AND r.event_type = 'contact_sync.failing'
      AND t.id <> default_tenant
      AND NOT EXISTS (
          SELECT 1 FROM notification_rules existing
          WHERE existing.tenant_id = t.id
            AND existing.event_type = r.event_type
      );
END $$;

COMMIT;
