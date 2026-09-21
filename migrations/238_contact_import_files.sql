-- PMS-1290 (PSA-70, vCard addendum): an uploaded `.vcf` file imports through
-- the same pipeline as Google Contacts.
--
-- ONE tenant-level `vcard` source row in `contact_sync_connections`, not one
-- row per upload. Links, review candidates, suppressions and runs all key on
-- `connection_id`, and a card's identity (its `UID`, else a digest of its
-- content) has to be recognised across uploads for a re-import of the same
-- file to create nothing: per-upload rows would scope that identity to one
-- file and every name-only card would be created again. The existing
-- `UNIQUE (tenant_id, provider) WHERE disconnected_at IS NULL` index already
-- gives exactly one such row.
--
-- What differs per upload (the file name, who uploaded it, when, what it held)
-- lives on `contact_import_files`, which the run, each link and each review
-- snapshot point at.

ALTER TABLE contact_sync_connections DROP CONSTRAINT contact_sync_connections_provider_check;
ALTER TABLE contact_sync_connections
    ADD CONSTRAINT contact_sync_connections_provider_check CHECK (provider IN ('google', 'vcard'));

CREATE TABLE contact_import_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The tenant's `vcard` source row.
    connection_id UUID NOT NULL REFERENCES contact_sync_connections(id) ON DELETE CASCADE,
    -- As the browser named it, sanitised and cut to fit. Shown, never used as
    -- a path: the stored object is addressed by `id` alone.
    filename VARCHAR(255) NOT NULL,
    byte_size BIGINT NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    uploaded_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- What the reader found, so the wizard and the import can be answered
    -- without reading the file again: every BEGIN:VCARD, the contacts among
    -- them, cards describing a group, per-card failures and warnings, and the
    -- selectable groups (`CATEGORIES`) with their counts.
    cards INTEGER NOT NULL,
    contacts INTEGER NOT NULL,
    group_cards INTEGER NOT NULL,
    failures JSONB NOT NULL DEFAULT '[]'::jsonb,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- The uploaded bytes are personal data held only as long as they are
    -- needed: discarded when the import run ends, and after this regardless.
    expires_at TIMESTAMPTZ NOT NULL,
    discarded_at TIMESTAMPTZ
);

CREATE INDEX idx_contact_import_files_recent
    ON contact_import_files (tenant_id, uploaded_at DESC);

-- The sweep that discards an abandoned upload.
CREATE INDEX idx_contact_import_files_held
    ON contact_import_files (expires_at)
    WHERE discarded_at IS NULL;

ALTER TABLE contact_import_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_import_files FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_import_files
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON contact_import_files TO mokosh_app;

-- The file a run imports. NULL for every Google run.
ALTER TABLE contact_sync_runs
    ADD COLUMN import_file_id UUID REFERENCES contact_import_files(id) ON DELETE SET NULL;

-- The file a link came from, for provenance: "imported from {filename} by
-- {user} on {date}". SET NULL, like the connection: losing the upload row
-- must never lose the record that the contact was imported.
ALTER TABLE contact_sync_links
    ADD COLUMN import_file_id UUID REFERENCES contact_import_files(id) ON DELETE SET NULL;
