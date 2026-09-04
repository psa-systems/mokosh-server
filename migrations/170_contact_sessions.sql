-- MAPPS-XXX (mokosh-contact-login prompt 002): refresh-token store for
-- contact sessions.
--
-- Contact access tokens live 15 min in JS memory; the refresh token
-- (30 day TTL) rotates them via `POST /api/v1/contact/auth/refresh`
-- (see prompt 004). The refresh token itself is minted as
-- `{session_id}.{secret}`; only the Argon2 hash of the secret half
-- is stored here so a leaked row cannot be turned back into a live
-- session. Rotation revokes the old row (sets `revoked_at`) and
-- issues a fresh one so any replay of the old refresh token flags
-- as revoked and 401s.
--
-- Separate from the pre-pivot `portal_refresh_tokens` (retired with
-- the /portal/* surface in prompt 001) so schemas can diverge cleanly
-- and a rollback to the parent branch does not step on this table.
CREATE TABLE contact_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_contact_sessions_hash
    ON contact_sessions (refresh_token_hash)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_contact_sessions_contact ON contact_sessions (contact_id);

ALTER TABLE contact_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_sessions
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
