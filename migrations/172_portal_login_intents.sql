-- PMS-918 (mokosh-contact-login prompt 010): magic-link login intents.
--
-- One row per `POST /api/v1/contact/auth/login-link` call that resolves
-- to a portal-enabled contact. The emailed link is `{intent.id}.{secret}`;
-- only the argon2 hash of the secret half is stored so a leaked row
-- cannot be turned back into a live login.
--
-- Column notes:
--   `email` (not `contact_id`) so a role revoke or portal-access revoke
-- between mint and click lands correctly - matching contacts runs at
-- redeem time and if none survive, the redeem returns the same generic
-- "invalid or expired" copy without leaking that revocation happened.
--
--   `ip` + `user_agent` capture the requester context so rate-limiting
-- can count per-IP + per-email without a separate side table.
--
--   `used_at IS NULL` selects the redeemable set; the partial index on
-- `secret_hash` keeps redeem lookups cheap even as the table grows.
--
-- Tenant-isolated via a FORCE'd RLS policy (same shape as
-- migrations 139-141 use for the portal_roles / contact_role_assignments /
-- contact_sessions family). The GUC is set transaction-locally by
-- `Database::begin_with_tenant`; genuinely cross-tenant / pre-auth
-- writes use the BYPASSRLS migrator pool with an explicit `// SAFETY:`
-- note in the service.
CREATE TABLE portal_login_intents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(320) NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    ip INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_portal_login_intents_tenant_email
    ON portal_login_intents (tenant_id, LOWER(email));
CREATE INDEX idx_portal_login_intents_active
    ON portal_login_intents (secret_hash)
    WHERE used_at IS NULL;

ALTER TABLE portal_login_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_login_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON portal_login_intents
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
