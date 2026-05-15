-- Authorization codes (OAuth 2.0 / OIDC Core code flow).
--
-- Single-use, short-lived (60s default), bound to client + redirect_uri +
-- PKCE challenge. The raw code never touches the database: only its
-- SHA-256 hash is stored, so a database leak does not let an attacker
-- replay codes still inside their TTL.

CREATE TABLE mokosh_auth.oauth_authorization_codes (
    code_hash              BYTEA        PRIMARY KEY,
    client_id              UUID         NOT NULL REFERENCES mokosh_auth.oauth_clients(client_id),
    user_id                UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id              UUID         NOT NULL,
    op_session_id          UUID         NOT NULL REFERENCES mokosh_auth.op_sessions(id) ON DELETE CASCADE,
    redirect_uri           TEXT         NOT NULL,
    scope                  TEXT[]       NOT NULL,
    code_challenge         TEXT         NOT NULL,
    code_challenge_method  TEXT         NOT NULL,
    nonce                  TEXT,
    auth_time              TIMESTAMPTZ  NOT NULL,
    acr                    TEXT         NOT NULL,
    amr                    TEXT[]       NOT NULL,
    issued_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at             TIMESTAMPTZ  NOT NULL,
    consumed_at            TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ,

    -- S256 only. Plain PKCE is rejected at the database layer too, not
    -- only in the application, so a future codepath that forgets the
    -- check still cannot persist a weaker code.
    CONSTRAINT oauth_codes_pkce_method_chk
        CHECK (code_challenge_method = 'S256'),
    -- code_hash is a 32-byte SHA-256.
    CONSTRAINT oauth_codes_hash_len_chk
        CHECK (octet_length(code_hash) = 32)
);

CREATE INDEX oauth_codes_session_idx
    ON mokosh_auth.oauth_authorization_codes (op_session_id);

CREATE INDEX oauth_codes_expires_idx
    ON mokosh_auth.oauth_authorization_codes (expires_at);
