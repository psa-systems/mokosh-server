-- Password reset tokens. Issued by POST /v1/auth/password-reset,
-- consumed by /v1/auth/password-reset/by-token/{token}/complete.
--
-- Same shape as mokosh_auth.signup_tokens (and admin_invites): 32-byte
-- SHA-256 hash for storage, raw token never persisted. used_at = NULL
-- means open; expires_at < now means dead regardless of used_at.
--
-- See docs/mokosh-smtp/05-password-reset.md.

CREATE TABLE mokosh_auth.password_reset_tokens (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    email       CITEXT       NOT NULL,
    token_hash  BYTEA        NOT NULL UNIQUE
        CHECK (octet_length(token_hash) = 32),
    issued_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ,
    -- Set on completion. ON DELETE SET NULL so a user delete does
    -- not cascade away the historical reset record.
    user_id     UUID
        REFERENCES mokosh_auth.users(id) ON DELETE SET NULL
);

CREATE INDEX password_reset_tokens_open_by_email
    ON mokosh_auth.password_reset_tokens(email)
    WHERE used_at IS NULL;
