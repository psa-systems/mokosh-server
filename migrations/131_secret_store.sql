-- PMS-967: a generic per-tenant secret store, so a credential's LOCATION is a
-- deployment choice rather than something each feature decides for itself.
--
-- Today every secret a tenant supplies is AES-256-GCM ciphertext in a column on
-- the feature's own table: `payment_gateway_configs.config_encrypted` is the
-- one that matters, encrypted with the host `ENCRYPTION_KEY` and decrypted
-- strictly server-side (PMS-342). That works, and it is the wrong place for the
-- decision: PMS-912 wants MSP-supplied integration credentials in Infisical,
-- and with the current shape that means teaching every feature about Infisical
-- one at a time.
--
-- This table is what the DATABASE backend of `crate::secrets` writes to, so the
-- default deployment keeps storing secrets in Postgres under the same
-- AES-256-GCM as before, and the Infisical backend is a configuration change
-- rather than a code change at the call site. It is the same bargain
-- `crate::storage` (PMS-910) made for files, with local as the default and S3
-- (PMS-958) selectable.
--
-- Nothing writes here yet. PMS-968 moves the payment-gateway credentials over;
-- this issue builds the seam and both backends, so the move lands against
-- something already tested.
--
-- `name` is the key's stable identity within a tenant, built by
-- `SecretKey::name` and validated there: a tenant id plus a kind plus the
-- kind's own discriminator. It is UNIQUE per tenant rather than globally,
-- because two tenants naming the same integration is the normal case.
--
-- `value_encrypted` is NOT NULL: a row here means a secret is stored. A secret
-- that has moved to another backend has no row, rather than a row with an empty
-- value, so "present but blank" is never a state anything has to interpret.

CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    value_encrypted TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_secrets_tenant ON secrets (tenant_id);

-- Fail-closed tenant isolation, same policy shape as every other tenant-scoped
-- table (038_rls_fail_closed.sql). A connection with no `app.current_tenant`
-- GUC set sees no rows rather than all of them, which for this table is the
-- difference between a bug and every tenant's credentials.
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secrets
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
