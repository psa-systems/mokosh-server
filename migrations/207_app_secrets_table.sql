-- PMS-988: application-tier secret storage for the database provider.
--
-- The tenant tier (`secrets`, migration numbers earlier in this repo) keys on
-- (tenant_id, name) and holds per-tenant integration credentials. This table
-- is deliberately separate and unscoped: application-tier secrets belong to
-- the whole process, not to any tenant, so a tenant column would be the wrong
-- shape (there is no tenant to set on the GUC and RLS has nothing to filter
-- on). One row per governed secret, keyed by its env-style name.
--
-- The value is AES-256-GCM ciphertext under the deployment's ENCRYPTION_KEY,
-- so a database dump does not reveal the value. Written and read exclusively
-- by `crate::app_secrets::database`; nothing else selects from this table.
--
-- No RLS, on purpose: app-tier means process-wide, not per-tenant, and RLS
-- with no tenant GUC to check against would either fail closed on every read
-- (making the table unreadable) or fail open (giving nothing).
CREATE TABLE app_secrets (
    name TEXT PRIMARY KEY,
    ciphertext BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The migrator owns the table; the request-serving `mokosh_app` role needs
-- read and write access. `provision_roles` already installs ALTER DEFAULT
-- PRIVILEGES for future tables the migrator creates, so this GRANT is
-- belt-and-braces documentation of intent: the row above says out loud that
-- the app role is the writer.
GRANT SELECT, INSERT, UPDATE, DELETE ON app_secrets TO mokosh_app;
