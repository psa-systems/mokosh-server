-- PMS-1214 (PSA-70 phase 4): unlink, disconnect and removal of imported data.
--
-- Migration 220 already carries the lock table and the tombstone column. What
-- it cannot say is WHY a link stopped, whether the import made the contact or
-- found it, or that a person asked for their imported data to be removed, and
-- all three decide what a later sync is allowed to do.

-- ============================================================================
-- 1. Whether the import created the contact or linked an existing one
-- ============================================================================
--
-- Removing a person's imported data (PSA-70 K) deletes a contact the import
-- CREATED, and leaves a contact that was already in the CRM, only removing
-- its link. The two are indistinguishable after the fact without this.
-- Nullable because a link written before the column has no honest answer, and
-- removal treats an unknown origin as `linked`: a guess that keeps a CRM record
-- is recoverable, a guess that deletes one is not.
ALTER TABLE contact_sync_links
    ADD COLUMN origin VARCHAR(16) CHECK (origin IN ('created', 'linked'));

-- ============================================================================
-- 2. Why a link stopped
-- ============================================================================
--
-- `unlinked` is a person choosing to stop syncing one contact, which the next
-- sync must respect rather than re-link by email a minute later.
-- `disconnected` is the connection going away (PSA-70 J): every contact stays
-- as a local record, and the link row stays as its provenance, still naming
-- the provider and the account it came from.
ALTER TABLE contact_sync_links
    ADD COLUMN unlink_reason VARCHAR(16) CHECK (unlink_reason IN ('unlinked', 'disconnected')),
    ADD COLUMN unlinked_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- ============================================================================
-- 3. contact_sync_suppressions - "do not import this person again"
-- ============================================================================
--
-- Removing imported data deletes the link row, and with it the only record
-- that the source holds this person, so without a marker the next sync imports
-- them straight back. The marker holds a SHA-256 of the provider's id rather
-- than the id: it has to recognise the record, not name it, and a removal that
-- keeps an identifier for the person it removed is only half a removal.
--
-- Keyed on the tenant and provider, not the connection: a disconnect and
-- reconnect of the same account must not undo a person's request.
CREATE TABLE contact_sync_suppressions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    external_id_sha256 CHAR(64) NOT NULL,
    reason VARCHAR(16) NOT NULL CHECK (reason IN ('data_removed')),
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, external_id_sha256)
);

ALTER TABLE contact_sync_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_sync_suppressions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_sync_suppressions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
