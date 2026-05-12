-- "Remember this browser for 7 days" tokens. Issued by
-- /v1/auth/mfa/verify when the user opts in; consumed by /v1/auth/login
-- to skip the MFA challenge on subsequent sign-ins from the same
-- browser. The raw token is held client-side; only the SHA-256 hash
-- persists here. Bound to one (user_id, tenant_id); a stolen token
-- alone does not let an attacker in without also knowing the password.

CREATE TABLE mokosh_auth.trusted_devices (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id    UUID         NOT NULL,
    token_hash   BYTEA        NOT NULL UNIQUE,
    issued_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ  NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    user_agent   TEXT,
    ip           INET,

    CONSTRAINT trusted_devices_hash_len_chk CHECK (octet_length(token_hash) = 32)
);

-- Login looks up the hash directly; the unique index above handles that.
-- For "list my trusted devices" + revocation we also need a user pivot.
CREATE INDEX trusted_devices_user_active_idx
    ON mokosh_auth.trusted_devices (user_id)
    WHERE revoked_at IS NULL;
