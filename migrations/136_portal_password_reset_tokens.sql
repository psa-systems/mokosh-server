-- PMS-729 phase 2 §5 H3: portal self-service password reset.
--
-- The customer clicks "forgot password?" on `/portal/login`, the SPA
-- POSTs `POST /portal/auth/forgot-password { email }`. Server-side
-- always returns 204 (enumeration-resistant); IF a portal contact
-- exists for that email under the resolved tenant, a fresh row lands
-- here and the customer receives an emailed link
-- `{portal_origin}/portal/reset-password?token={id}.{secret}`.
--
-- Redeem via `POST /portal/auth/reset-password { token, password }`.
-- Same status contract as the setup-password token (PMS-136):
--   - valid, unused, unexpired -> sets `portal_password_hash`, marks
--     the token used, returns 204.
--   - already redeemed -> 410 Gone.
--   - expired -> 400.
--   - no matching token -> 400 (indistinguishable from expired).
--
-- Storage: only the Argon2id hash of the secret. Plaintext leaves
-- server memory once, in the outbound email. A DB compromise cannot
-- replay a token.

CREATE TABLE portal_password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    -- Set when the customer redeems the token via reset-password. A
    -- non-NULL value flips subsequent redemptions to 410 Gone.
    used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Optional context captured at request time for the audit trail.
    -- Not user input; the route pulls them from the request itself.
    requested_from_ip INET,
    requested_from_user_agent TEXT
);

-- Fast lookup by contact for the "live tokens for this account" case.
-- Partial index keeps the working set tiny; only unused, unexpired
-- rows can be redeemed.
CREATE INDEX idx_portal_password_reset_contact_live
    ON portal_password_reset_tokens (contact_id, expires_at)
    WHERE used_at IS NULL;

-- Tenant-scoping index for admin reports later on (e.g. "how many
-- resets did tenant X request last week"). Small; keeps a per-tenant
-- scan bounded even with heavy churn.
CREATE INDEX idx_portal_password_reset_tenant
    ON portal_password_reset_tokens (tenant_id);

-- RLS: tenant-isolated exactly like the sibling portal_setup_tokens +
-- portal_refresh_tokens tables. The migrator pool bypasses via
-- BYPASSRLS; the request-serving app pool sees only its own tenant.
ALTER TABLE portal_password_reset_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON portal_password_reset_tokens
    USING (tenant_id::text = current_setting('app.current_tenant', TRUE));

COMMENT ON TABLE portal_password_reset_tokens IS
    'PMS-729 phase 2 H3: single-use reset tokens for the client portal. See docs/mokosh-client-login/phase-2-plan.md §5.';
