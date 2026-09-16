-- PMS-1212 (PSA-70 phase 2): the in-flight half of an OAuth connect.
--
-- Between "an admin pressed Connect" and "Google redirected them back" there
-- are two things the callback needs and the browser must not be trusted to
-- carry: WHO started this, and the PKCE `code_verifier`. Both live here for the
-- few minutes the consent screen is open.
--
-- The callback is reached by a browser redirect from Google and carries no
-- session, so this row IS the credential. It follows the PMS-136 setup-token
-- shape exactly: the caller holds `{id}.{secret}`, the table holds the id and
-- an Argon2 hash of the secret, so a leaked database row cannot be replayed as
-- a state parameter. Single use (`consumed_at`) and short lived
-- (`expires_at`), because a state that can be replayed is a CSRF hole and one
-- that never expires is a permanent one.
CREATE TABLE contact_sync_oauth_states (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL CHECK (provider IN ('google')),
    -- Who pressed Connect. The connection they end up owning records them as
    -- `connected_by_user_id`, and the audit row names them.
    started_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Argon2 hash of the secret half of the state parameter.
    state_hash VARCHAR(255) NOT NULL,
    -- PKCE. The verifier never leaves this row until the token exchange, which
    -- is the whole point of PKCE: an intercepted authorization code is useless
    -- without it.
    code_verifier VARCHAR(255) NOT NULL,
    -- The exact redirect_uri sent with the authorization request. Google
    -- requires the token exchange to repeat it byte for byte, and a
    -- deployment can legitimately change `PUBLIC_API_BASE_URL` while a
    -- consent screen is open.
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contact_sync_oauth_states_sweep
    ON contact_sync_oauth_states (expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE contact_sync_oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_sync_oauth_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_sync_oauth_states
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
