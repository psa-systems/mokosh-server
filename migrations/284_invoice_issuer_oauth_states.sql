-- MAPPS-1142: the single-use state an invoice-issuer OAuth round trip hangs on.
--
-- Its own table rather than a wider CHECK on `contact_sync_oauth_states`,
-- which is contact sync's: the two flows share a shape and nothing else. One
-- table would mean a provider list that spans two subsystems, an RLS policy
-- two features depend on, and a sweep that cannot be reasoned about without
-- knowing both. The shape is copied deliberately (PSA-70, MAPPS-1101) because
-- a second shape for one problem is a second thing to get wrong.
--
-- What the row holds and why each piece is here:
--
-- The STATE SECRET is stored as an argon2 hash, never in the clear. The
-- callback arrives on a public route and proves possession by presenting the
-- secret; a row that held it would turn a database read into a working
-- consent.
--
-- The PKCE VERIFIER never leaves this row until the token exchange, which is
-- the point of PKCE: an intercepted authorization code is useless without it.
-- Both providers accept it on a confidential client, and both are given one.
--
-- The REDIRECT URI is stored because the token exchange has to repeat it byte
-- for byte, and a deployment can legitimately change `PUBLIC_API_BASE_URL`
-- while a consent screen is open.
--
-- `consumed_at` is set BEFORE the exchange, so a slow or failing exchange
-- cannot be replayed with the same state.
--
-- PMS-1265: granted to `mokosh_app`, which is the role that serves.

CREATE TABLE IF NOT EXISTS invoice_issuer_oauth_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL CHECK (provider IN ('xero', 'quickbooks')),
    -- Who pressed Connect. The integrations row they end up owning records
    -- them, and the audit row names them.
    started_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state_hash VARCHAR(255) NOT NULL,
    code_verifier VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoice_issuer_oauth_states_sweep
    ON invoice_issuer_oauth_states (expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE invoice_issuer_oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_issuer_oauth_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoice_issuer_oauth_states
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_issuer_oauth_states TO mokosh_app;
