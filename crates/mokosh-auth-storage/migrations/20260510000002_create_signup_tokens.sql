-- Signup tokens. The unauthenticated POST /v1/auth/signup endpoint
-- stores a row here and emails the bearer a link
-- (<accept_base_url>/signup/<raw_token>); the link's
-- /v1/auth/signup/by-token/{token}/complete handler completes the
-- account creation under SERIALIZABLE.
--
-- Same shape as mokosh_auth.admin_invites: 32-byte SHA-256 hash for
-- storage, raw token never persisted. used_at = NULL means the token
-- is open. expires_at < now means the token is dead even if used_at
-- is still NULL.
--
-- See docs/mokosh-auth/10-memberships-and-self-signup.md (phase 2).

CREATE TABLE mokosh_auth.signup_tokens (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    email       CITEXT       NOT NULL,
    -- 32 raw bytes (output of SHA-256 over the URL-safe random token).
    token_hash  BYTEA        NOT NULL UNIQUE
        CHECK (octet_length(token_hash) = 32),
    issued_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ,
    -- Set on completion. ON DELETE SET NULL via the FK so a user-row
    -- delete does not cascade away the historical signup record.
    user_id     UUID
        REFERENCES mokosh_auth.users(id) ON DELETE SET NULL
);

-- Lookups:
--   - by token_hash  (preview / complete)
--   - by email + open  (rate-limit + "already requested?")
CREATE INDEX signup_tokens_open_by_email
    ON mokosh_auth.signup_tokens(email)
    WHERE used_at IS NULL;
