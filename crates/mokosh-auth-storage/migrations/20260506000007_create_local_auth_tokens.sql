-- Short-lived single-use tokens used by the OP's own login UI.
-- All four tables follow the same shape: store SHA-256(raw_token), expiry,
-- single-use marker, originating IP for audit.

-- Password reset (1-hour TTL).
CREATE TABLE mokosh_auth.password_reset_tokens (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id   UUID         NOT NULL,
    token_hash  BYTEA        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    ip          INET,

    CONSTRAINT password_reset_hash_len_chk CHECK (octet_length(token_hash) = 32)
);
CREATE INDEX password_reset_user_idx ON mokosh_auth.password_reset_tokens (user_id);

-- Magic link (15-minute TTL, rate-limited at the application layer).
CREATE TABLE mokosh_auth.magic_link_tokens (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Email is stored, not user_id, because magic-link login can be
    -- offered before a user record exists (signup-by-link). Resolution to
    -- a user_id happens at consumption time.
    email       CITEXT       NOT NULL,
    tenant_id   UUID         NOT NULL,
    token_hash  BYTEA        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    ip          INET,

    CONSTRAINT magic_link_hash_len_chk CHECK (octet_length(token_hash) = 32)
);
CREATE INDEX magic_link_email_idx ON mokosh_auth.magic_link_tokens (email);

-- Initial email verification (sent at registration / by admin invite).
CREATE TABLE mokosh_auth.email_verification_tokens (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id   UUID         NOT NULL,
    token_hash  BYTEA        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT email_verify_hash_len_chk CHECK (octet_length(token_hash) = 32)
);
CREATE INDEX email_verify_user_idx ON mokosh_auth.email_verification_tokens (user_id);

-- Email-change confirmation (user changes their address; we send a
-- confirmation link to the *new* address before swapping it in).
CREATE TABLE mokosh_auth.email_change_requests (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id    UUID         NOT NULL,
    new_email    CITEXT       NOT NULL,
    token_hash   BYTEA        NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ  NOT NULL,
    confirmed_at TIMESTAMPTZ,
    canceled_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    ip           INET,

    CONSTRAINT email_change_hash_len_chk CHECK (octet_length(token_hash) = 32)
);
CREATE INDEX email_change_user_idx ON mokosh_auth.email_change_requests (user_id);
