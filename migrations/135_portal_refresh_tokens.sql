-- PMS-729 phase 2 §5 H1+H2: portal refresh tokens (docs/mokosh-client-login/phase-2-plan.md §5.4).
--
-- Portal auth today mints a single long-lived access JWT (~8h). This is too
-- long for a stolen token and there is no way to invalidate one server-side
-- when the customer logs out. The refresh-token model:
--
--   1. `POST /portal/auth/login`      -> returns a short access JWT (~15 min)
--                                        AND a refresh token (~30 days, one
--                                        `portal_refresh_tokens` row).
--   2. `POST /portal/auth/refresh`    -> rotates: revokes the presented refresh
--                                        token and mints a new one, plus a new
--                                        access JWT. Replay-detection: if the
--                                        SAME refresh token is presented twice
--                                        (already-rotated), every live token in
--                                        the same rotation chain is revoked
--                                        as a precaution (stolen-token signal).
--   3. `POST /portal/auth/logout`     -> revokes the presented refresh token
--                                        AND every token in its rotation chain.
--                                        The access JWT expires on its own; no
--                                        server-side access-token store.
--
-- Storage: only the HASH of the token secret. The plaintext is returned once at
-- issue time. Even a database compromise cannot replay a token.
--
-- Rotation chain: `rotated_from_id` points at the ancestor row. Following the
-- chain (recursive CTE) gives the full family; if any descendant is presented
-- more than once, every family member gets `revoked_at` stamped.

CREATE TABLE portal_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    -- Argon2id hash of the token secret (`utils::crypto::hash_password`).
    -- Same primitive as the setup-token hash so we do not add a new hashing
    -- posture just for this.
    token_hash TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- Ancestor row in the rotation chain, or NULL for the initial issuance
    -- (`POST /portal/auth/login`). Follow up the chain via a recursive CTE
    -- to detect replay.
    rotated_from_id UUID REFERENCES portal_refresh_tokens(id) ON DELETE SET NULL,
    -- Set when the token has been rotated (moved forward) or explicitly
    -- revoked (logout, replay-detected). NULL = live.
    revoked_at TIMESTAMPTZ,
    -- Advisory context captured at issuance for the customer's session
    -- list surface (§5.5 GET /portal/auth/me/sessions, later phase).
    user_agent TEXT,
    ip_address INET
);

-- Fast lookup by (contact_id) for the /sessions surface + logout-all path.
-- Filtered on `revoked_at IS NULL` to keep the index small; live tokens are
-- the only ones we ever fetch by contact.
CREATE INDEX idx_portal_refresh_tokens_contact_live
    ON portal_refresh_tokens (contact_id, expires_at)
    WHERE revoked_at IS NULL;

-- Chain traversal from a rotated ancestor to its descendants.
CREATE INDEX idx_portal_refresh_tokens_rotated_from
    ON portal_refresh_tokens (rotated_from_id)
    WHERE rotated_from_id IS NOT NULL;

-- Tenant-scoping index for the PMS-285 RLS pool. Portal auth reads run on
-- the migrator pool today, but future tenant-scoped reads (e.g. an admin
-- report on portal sessions per tenant) should not scan the whole table.
CREATE INDEX idx_portal_refresh_tokens_tenant
    ON portal_refresh_tokens (tenant_id);

-- RLS: tenant-isolated exactly like every other portal-touching table
-- (contacts, portal_setup_tokens). The migrator pool bypasses via
-- BYPASSRLS; the request-serving app pool sees only its own tenant.
ALTER TABLE portal_refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON portal_refresh_tokens
    USING (tenant_id::text = current_setting('app.current_tenant', TRUE));

COMMENT ON TABLE portal_refresh_tokens IS
    'PMS-729 phase 2 H1+H2: server-side refresh tokens for the client portal. See docs/mokosh-client-login/phase-2-plan.md §5.4.';
