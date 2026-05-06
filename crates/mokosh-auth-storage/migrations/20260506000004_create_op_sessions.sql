-- OP-side authentication sessions. Created when a user logs in to the
-- mokosh-auth login UI; identified by an opaque `sid` placed in the
-- `mokosh_op_session` browser cookie. Distinct from refresh tokens:
-- killing an OP session also invalidates the cookie used to mint new
-- authorization codes from this browser.

CREATE TABLE mokosh_auth.op_sessions (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Opaque, base64url, never logged. Indexed because every authenticated
    -- request looks up by this column.
    sid             TEXT         NOT NULL UNIQUE,
    user_id         UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id       UUID         NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_active_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ  NOT NULL,
    revoked_at      TIMESTAMPTZ,
    user_agent      TEXT,
    ip              INET,
    -- Authentication Context Class Reference. Defaults to password-only;
    -- a future MFA-backed login would set this to a stronger value, which
    -- relying parties can require via `acr_values`.
    acr             TEXT         NOT NULL DEFAULT 'urn:mokosh:loa:pwd',
    -- Authentication Methods References (OIDC Core 2).
    amr             TEXT[]       NOT NULL DEFAULT ARRAY['pwd']::TEXT[]
);

CREATE INDEX op_sessions_user_active_idx
    ON mokosh_auth.op_sessions (user_id)
    WHERE revoked_at IS NULL;

-- Cron-driven cleanup of expired/revoked sessions runs against this index.
CREATE INDEX op_sessions_expires_idx
    ON mokosh_auth.op_sessions (expires_at)
    WHERE revoked_at IS NULL;
