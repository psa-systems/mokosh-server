-- PMS-1211 (PSA-70 phase 1): one-way contact import from an external directory.
--
-- Google is the only provider this epic implements, and the shape is the RMM
-- integration's (migration 014): a connection row per provider carrying the
-- schedule and the last outcome, and a mapping child keyed on the provider's
-- own id. That pattern has carried four provider discriminators against one
-- implementation since 2024, which is the whole argument for copying it rather
-- than inventing a second external-identity shape for Microsoft 365 (PSA-11)
-- to break later.
--
-- Two rules this schema enforces rather than documents.
--
-- ONE-WAY. Nothing here records anything to send back to Google. There is no
-- outbound queue, no dirty flag, no pending-write column, because the OAuth
-- scope requested (PMS-1212) is `contacts.readonly` and a write is not
-- something a bug could perform.
--
-- ORG-LEVEL. `UNIQUE (tenant_id, provider)` is the decision on PSA-70 (B): the
-- business connects one Workspace account, an admin does it once, and the
-- imported contacts belong to the tenant. Per-user connections are not a
-- column left unread here: they would need per-user visibility on imported
-- contacts, a disconnect that does not orphan a colleague's links, and consent
-- that survives the technician leaving, none of which this schema pretends to
-- carry.

-- ============================================================================
-- 1. contact_sync_connections
-- ============================================================================
CREATE TABLE contact_sync_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The discriminator a provider implementation is built from, the
    -- `rmm_connections.provider` shape. CHECKed to what this build serves, so
    -- a row cannot name a provider nothing can read.
    provider VARCHAR(32) NOT NULL CHECK (provider IN ('google')),
    -- Who connected it, for the audit trail and for "ask them before you
    -- disconnect". SET NULL because a connection outlives the admin who made
    -- it, and losing the account would otherwise take the integration with it.
    connected_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    -- The connected account, shown in Settings so an admin can tell which
    -- Google account this is without opening Google. Not a credential.
    account_email VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 60
        CHECK (sync_interval_minutes >= 5),
    last_sync_at TIMESTAMPTZ,
    -- `throttled` and `reconnect_required` are their own outcomes rather than
    -- flavours of `failed` (PSA-70 J): a rate limit is the provider asking us
    -- to wait and must not read as a broken integration, and a revoked grant
    -- is the one state where a human has something to do.
    sync_status VARCHAR(24) NOT NULL DEFAULT 'never' CHECK (
        sync_status IN (
            'never', 'in_progress', 'success', 'failed',
            'throttled', 'reconnect_required'
        )
    ),
    last_error TEXT,
    -- People API incremental cursor. Opaque, and expires: `410
    -- EXPIRED_SYNC_TOKEN` falls back to a full resync (PMS-1213), so a NULL
    -- here means "next sync is a full one" rather than an error.
    sync_token TEXT,
    -- The contact groups an admin opted into, as provider group ids. Empty
    -- means nothing has been selected yet and no import should run: a blank
    -- selection must never read as "import everything" (PSA-70 E).
    selected_groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- When an admin disconnected. The row is KEPT (PSA-70 J): imported
    -- contacts stay as local records, and their provenance has to keep
    -- naming where they came from.
    disconnected_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One live connection per provider per tenant: the org-level decision, in the
-- schema. Partial, so a disconnected row stays for provenance and a later
-- reconnect is not blocked by it.
CREATE UNIQUE INDEX idx_contact_sync_connections_live
    ON contact_sync_connections (tenant_id, provider)
    WHERE disconnected_at IS NULL;

CREATE INDEX idx_contact_sync_connections_due
    ON contact_sync_connections (tenant_id, last_sync_at)
    WHERE is_active AND disconnected_at IS NULL;

-- ============================================================================
-- 2. contact_sync_links - the provenance record (PSA-70 C)
-- ============================================================================
CREATE TABLE contact_sync_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- SET NULL, not CASCADE: deleting a connection must never delete the
    -- record of where a contact came from. `provider` and
    -- `source_account_email` are copied here for exactly that reason - after
    -- a disconnect the contact is a local record that can still say it was
    -- imported from Google, and from which account (PSA-70 J).
    connection_id UUID REFERENCES contact_sync_connections(id) ON DELETE SET NULL,
    provider VARCHAR(32) NOT NULL,
    source_account_email VARCHAR(255) NOT NULL,
    -- People API `resourceName`, e.g. `people/c12345`. The provider's own id,
    -- never parsed for meaning.
    external_id VARCHAR(255) NOT NULL,
    -- People API `etag`: the version. An unchanged etag is the cheapest
    -- "nothing to do" there is, which is half of idempotency (PSA-70 I).
    etag VARCHAR(255),
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    last_synced_at TIMESTAMPTZ,
    -- Set when the source says the record is gone. It archives nothing and
    -- deletes nothing (PSA-70 I): somebody tidying their phone must not remove
    -- a customer contact from the CRM.
    deleted_in_source_at TIMESTAMPTZ,
    -- Set when a human unlinks this contact, which leaves the contact intact
    -- and stops it being synced.
    unlinked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One live link per external record per connection. Partial so an unlinked or
-- orphaned row stays as history without blocking a re-import.
CREATE UNIQUE INDEX idx_contact_sync_links_live
    ON contact_sync_links (connection_id, external_id)
    WHERE unlinked_at IS NULL AND connection_id IS NOT NULL;

CREATE INDEX idx_contact_sync_links_contact
    ON contact_sync_links (tenant_id, contact_id);

-- ============================================================================
-- 3. contact_field_locks - the conflict rule (PSA-70 H)
-- ============================================================================
--
-- A field a human edited in Mokosh is locked against sync. The alternative,
-- source always wins, silently discards the correction somebody made on
-- purpose, which is the failure that makes people stop trusting an
-- integration and start keeping a spreadsheet beside it.
--
-- One row per locked field rather than a JSONB set on the contact: the lock is
-- queried per field on every sync write, released per field by a human, and
-- has its own who and when.
CREATE TABLE contact_field_locks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    -- The Mokosh field name as the mapping table (PSA-70 F) spells it, e.g.
    -- `first_name`, `email`, `title`. Not CHECKed against a list here: the
    -- writer validates against the mapping, and a CHECK would be a second,
    -- drifting copy of it in a place migrations cannot change.
    field VARCHAR(64) NOT NULL,
    locked_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    locked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (contact_id, field)
);

CREATE INDEX idx_contact_field_locks_contact
    ON contact_field_locks (tenant_id, contact_id);

-- ============================================================================
-- 4. contact_sync_candidates - the review queue (PSA-70 D)
-- ============================================================================
--
-- Anything short of an exact normalized-email match is a question for a human,
-- never an automatic merge. One row per (external record, Mokosh candidate)
-- PAIR, which is what makes both awkward shapes representable: one Google
-- contact matching two Mokosh contacts is two rows sharing `external_id`, and
-- two Google contacts matching one Mokosh contact is two rows sharing
-- `candidate_contact_id`. A single row per external record could not express
-- the second, and the client has to warn about it.
CREATE TABLE contact_sync_candidates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- CASCADE here, unlike the links: an open question about a connection that
    -- no longer exists is not history worth keeping, it is a queue item nobody
    -- can answer.
    connection_id UUID NOT NULL REFERENCES contact_sync_connections(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    etag VARCHAR(255),
    candidate_contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    -- Why this pair was proposed. `email` never appears here: an exact
    -- normalized email match links automatically and never reaches the queue.
    match_reason VARCHAR(24) NOT NULL CHECK (
        match_reason IN ('phone', 'name_company')
    ),
    -- The incoming record as the provider gave it, normalised to the shape the
    -- side-by-side comparison renders. Held here so the queue can be answered
    -- without a second call to Google, and so a decision made days later
    -- compares against what was actually seen.
    source_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(16) NOT NULL DEFAULT 'open' CHECK (
        status IN ('open', 'linked', 'created', 'skipped')
    ),
    resolved_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One open question per pair. A re-sync that sees the same ambiguity finds
-- this row instead of queueing the question again, which is what keeps the
-- queue idempotent (PSA-70 I).
CREATE UNIQUE INDEX idx_contact_sync_candidates_open
    ON contact_sync_candidates (connection_id, external_id, candidate_contact_id)
    WHERE status = 'open';

CREATE INDEX idx_contact_sync_candidates_queue
    ON contact_sync_candidates (tenant_id, status, created_at DESC);

-- ============================================================================
-- 5. RLS, fail closed, on all four
-- ============================================================================
-- The 024 / 038 sweeps ran before these tables existed, so the same shape is
-- attached explicitly. FORCE so the app pool (NOBYPASSRLS) cannot escape it.
ALTER TABLE contact_sync_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_sync_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_sync_connections
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

ALTER TABLE contact_sync_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_sync_links FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_sync_links
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

ALTER TABLE contact_field_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_field_locks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_field_locks
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

ALTER TABLE contact_sync_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_sync_candidates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_sync_candidates
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
