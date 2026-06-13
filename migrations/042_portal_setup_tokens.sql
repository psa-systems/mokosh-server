-- PMS-136: portal-access setup tokens.
--
-- Mirrors `password_reset_tokens` (003_auth.sql) but binds to a `contacts`
-- row instead of a `users` row. When an MSP agent grants portal access to a
-- contact (`create_portal_access` on create, or `is_portal_user = true` on
-- update), one row is inserted and a `/portal/set-password` link is emailed.
-- The customer redeems the token to mint their initial `portal_password_hash`
-- so they can sign in via the PMS-26 portal session endpoint.
--
-- The emailed token is `{contact_id}.{secret}`; only the Argon2 hash of the
-- secret half is stored, so a leaked row cannot be turned back into a link.
-- Tokens auto-expire after 72h (mirrors the reset-token redemption window).

CREATE TABLE portal_setup_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_portal_setup_token ON portal_setup_tokens(token_hash);
CREATE INDEX idx_portal_setup_contact ON portal_setup_tokens(contact_id);

-- Row-level security. The fail-closed `tenant_isolation` policy is attached
-- by a DO-block loop over `information_schema` in 024/038, but those loops
-- already ran, so a table created now does NOT inherit the policy. Attach the
-- same fail-closed, FORCE'd policy explicitly (PMS-257 posture) so
-- portal_setup_tokens is tenant-isolated the moment the application drops its
-- BYPASSRLS role. The GUC is set transaction-locally by
-- `Database::begin_with_tenant` (src/db/pool.rs).
ALTER TABLE portal_setup_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_setup_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON portal_setup_tokens
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
