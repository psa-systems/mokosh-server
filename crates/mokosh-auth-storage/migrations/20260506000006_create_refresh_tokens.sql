-- Refresh tokens with family-level reuse detection.
--
-- Every refresh token belongs to a "family". The first token in a family
-- is created when the OP issues tokens for an authorization code; each
-- successful rotation creates a new sibling and marks the previous one
-- used. Presenting an already-used token is a replay: we revoke the
-- entire family (so a stolen older token cannot keep refreshing) and
-- emit a critical audit event.
--
-- This file creates two tables that always go together. They are kept in
-- one migration so they cannot get out of sync at any point in history.

CREATE TABLE mokosh_auth.refresh_token_families (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id       UUID         NOT NULL REFERENCES mokosh_auth.oauth_clients(client_id),
    user_id         UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id       UUID         NOT NULL,
    op_session_id   UUID         REFERENCES mokosh_auth.op_sessions(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,
    revoke_reason   TEXT
);

CREATE INDEX refresh_families_user_idx
    ON mokosh_auth.refresh_token_families (user_id)
    WHERE revoked_at IS NULL;

CREATE TABLE mokosh_auth.refresh_tokens (
    id                    UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    family_id             UUID         NOT NULL REFERENCES mokosh_auth.refresh_token_families(id) ON DELETE CASCADE,
    -- Pointer to the row that this one rotated from. Useful for forensic
    -- analysis when a reuse is detected.
    parent_id             UUID         REFERENCES mokosh_auth.refresh_tokens(id) ON DELETE SET NULL,
    -- SHA-256 of the raw refresh token. The raw token is returned to the
    -- client exactly once; the hash is the only persistent record.
    token_hash            BYTEA        NOT NULL UNIQUE,
    client_id             UUID         NOT NULL,
    user_id               UUID         NOT NULL,
    tenant_id             UUID         NOT NULL,
    scope                 TEXT[]       NOT NULL,
    -- DPoP JWK thumbprint (RFC 9449). Phase-2 column.
    cnf_jkt               TEXT,
    issued_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- Set when the token is consumed by a successful rotation. Combined
    -- with SERIALIZABLE isolation in the rotate query, this is what makes
    -- replay detection race-free.
    used_at               TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    -- Sliding window: each successful rotation pushes this forward.
    idle_expires_at       TIMESTAMPTZ  NOT NULL,
    -- Hard cap inherited from the family; never extended.
    absolute_expires_at   TIMESTAMPTZ  NOT NULL,
    ip                    INET,
    user_agent            TEXT,

    CONSTRAINT refresh_tokens_hash_len_chk
        CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX refresh_tokens_family_idx
    ON mokosh_auth.refresh_tokens (family_id);

CREATE INDEX refresh_tokens_user_active_idx
    ON mokosh_auth.refresh_tokens (user_id)
    WHERE revoked_at IS NULL AND used_at IS NULL;

-- Cleanup index: drives a cron job that purges fully-expired rows.
CREATE INDEX refresh_tokens_absolute_expires_idx
    ON mokosh_auth.refresh_tokens (absolute_expires_at);
