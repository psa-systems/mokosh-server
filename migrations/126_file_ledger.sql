-- PMS-957: make the `files` ledger writable, and fill in what is already known.
--
-- `files` was created by the PMS-128 split and never written to. Its only
-- reference in the whole codebase is `SELECT COALESCE(SUM(file_size), 0) FROM
-- files WHERE tenant_id = $1`, which feeds `TenantUsage.storage_bytes` on the
-- tenants API, so every tenant's reported storage usage has always been a
-- constant zero and stayed zero however much they uploaded.
--
-- It is worth filling rather than removing. The columns are exactly what a
-- storage subsystem needs and PMS-910 has just given them one place to be
-- written from; summing three feature tables plus a filesystem stat instead
-- would be three places to remember when a fourth kind of upload appears.

-- An upload does not always have a `users` row behind it. A ticket attachment
-- can come from the customer portal, where the actor is a `contacts` row, or
-- from inbound email (PMS-450), where there is no actor at all;
-- `ticket_attachments` already models this with a nullable `uploaded_by_id`
-- beside `created_by_contact_id`. The ledger could not record either, so the
-- column that was going to refuse the row loses its NOT NULL.
ALTER TABLE files ALTER COLUMN uploaded_by_id DROP NOT NULL;

-- `storage_path` holds the path BELOW the storage root, not an absolute one.
-- The root is runtime configuration that differs between a dev container and a
-- production volume, so an absolute path baked into a row goes stale the first
-- time a deployment moves it - which is the lesson `ticket_attachments` taught,
-- whose absolute `storage_path` PMS-910 stopped reading. It is also what makes
-- the backfill below possible at all: a relative path is derivable in SQL from
-- ids the feature tables already hold.
COMMENT ON COLUMN files.storage_path IS
    'Path below the storage root (crate::storage), never absolute: the root is deployment configuration. PMS-957.';

-- The rollup this table exists to answer.
CREATE INDEX IF NOT EXISTS idx_files_tenant_size ON files (tenant_id, file_size);

-- One row per object already stored, from the feature tables that recorded a
-- size. This is what stops every existing tenant reading zero on the day the
-- writes start, which would otherwise look like the bug getting worse.
--
-- The paths match `ObjectKey::relative_path` exactly, and the storage-module
-- test that pins the layout is what keeps the two honest.
INSERT INTO files (
    id, tenant_id, original_name, storage_path, mime_type, file_size,
    uploaded_by_id, entity_type, entity_id, created_at
)
SELECT
    ta.id,
    ta.tenant_id,
    ta.file_name,
    ta.tenant_id || '/' || ta.id,
    ta.mime_type,
    ta.file_size,
    ta.uploaded_by_id,
    'ticket_attachment',
    ta.id,
    ta.created_at
FROM ticket_attachments ta
ON CONFLICT (id) DO NOTHING;

INSERT INTO files (
    id, tenant_id, original_name, storage_path, mime_type, file_size,
    uploaded_by_id, entity_type, entity_id, created_at
)
SELECT
    ka.id,
    ka.tenant_id,
    ka.file_name,
    'kb-articles/' || ka.id,
    ka.mime_type,
    ka.file_size,
    ka.uploaded_by_id,
    'kb_attachment',
    ka.id,
    ka.created_at
FROM kb_article_attachments ka
ON CONFLICT (id) DO NOTHING;

-- Tenant logos are deliberately NOT backfilled. Nothing records a logo's size:
-- the branding row carries its mime type and the bytes are on disk, and a
-- migration cannot stat a file. Backfilling a guess would put a made-up number
-- into the figure this issue exists to make true. A logo is capped at 1 MiB by
-- default, so the omission is bounded, and every logo uploaded from here is
-- recorded like anything else.
