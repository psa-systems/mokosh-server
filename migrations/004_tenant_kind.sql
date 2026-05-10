-- Distinguish personal tenants (one per self-signed-up user) from org
-- tenants (multi-user, the existing PSA model). The auth crate's
-- self-signup flow inserts kind='personal'; admin-invite flows continue
-- to live in kind='org' tenants.
--
-- See docs/mokosh-auth/10-memberships-and-self-signup.md.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'org'
        CHECK (kind IN ('personal', 'org'));

-- Existing tenants stay 'org' (the historic PSA model). The default is
-- there only for backfill; the column is otherwise required and
-- callers always set it explicitly.
ALTER TABLE tenants
    ALTER COLUMN kind DROP DEFAULT;

CREATE INDEX IF NOT EXISTS idx_tenants_kind ON tenants(kind);
