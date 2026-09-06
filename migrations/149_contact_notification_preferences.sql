-- Portal notification-preferences table.
--
-- Per-(contact, event_type) opt-in the portal Settings page reads
-- and writes. Absent row = accept the default rule fanout (matches
-- the `user_notification_preferences` posture). Row with
-- `is_enabled = FALSE` = suppress every channel for that event.
-- `channel_types` picks WHICH channels the contact still wants when
-- `is_enabled = TRUE`; empty array means accept every channel.
--
-- Mirrors the shape of `user_notification_preferences` (migration 013)
-- so the dispatcher check + preference-row loader can be a
-- straight parallel of the existing user-side machinery. Kept in
-- its own table (not folded into the user one) so the FK to
-- `contacts(id)` stays sound and the RLS tenant policy is cleanly
-- scoped to contacts, not users.

CREATE TABLE contact_notification_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    channel_types VARCHAR(20)[] NOT NULL DEFAULT ARRAY[]::VARCHAR(20)[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (contact_id, event_type)
);

CREATE INDEX idx_contact_notification_prefs_tenant
    ON contact_notification_preferences (tenant_id);

CREATE INDEX idx_contact_notification_prefs_lookup
    ON contact_notification_preferences (tenant_id, contact_id, event_type);

-- RLS: per-tenant isolation via the app.current_tenant GUC, same
-- pattern every RLS-covered table on this project uses. The
-- dispatcher runs under a tenant GUC (`begin_with_tenant`) so its
-- SELECTs pass; the portal settings handlers do the same for
-- reads + upserts.
ALTER TABLE contact_notification_preferences ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_contact_notification_prefs
    ON contact_notification_preferences
    USING (tenant_id = current_setting('app.current_tenant', TRUE)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', TRUE)::UUID);
