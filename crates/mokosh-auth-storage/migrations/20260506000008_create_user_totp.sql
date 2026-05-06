-- TOTP (RFC 6238) second factor.
--
-- The TOTP shared secret is encrypted with AES-256-GCM under a key from
-- env / Infisical, with `key_version` selecting which key decrypts. This
-- gives us zero-downtime rotation: write under a new version, keep the
-- old key around long enough to re-encrypt all rows.

CREATE TABLE mokosh_auth.user_totp (
    id                UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id           UUID         NOT NULL UNIQUE REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id         UUID         NOT NULL,
    -- Serialized EncryptedBlob { version, nonce, ciphertext } as JSONB so
    -- we never accidentally store the raw secret.
    secret_encrypted  JSONB        NOT NULL,
    key_version       SMALLINT     NOT NULL,
    -- A user may set up TOTP and only confirm it later; until confirmed,
    -- this row is treated as not-yet-active.
    confirmed_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Recovery codes printed at TOTP setup time. Hashed with SHA-256 (the
-- codes themselves are 80 random bits, so SHA-256 is sufficient: there
-- is no offline-grinding threat the way there is for passwords).
CREATE TABLE mokosh_auth.recovery_codes (
    id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_totp_id  UUID         NOT NULL REFERENCES mokosh_auth.user_totp(id) ON DELETE CASCADE,
    user_id       UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id     UUID         NOT NULL,
    code_hash     BYTEA        NOT NULL UNIQUE,
    used_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT recovery_codes_hash_len_chk CHECK (octet_length(code_hash) = 32)
);
CREATE INDEX recovery_codes_user_unused_idx
    ON mokosh_auth.recovery_codes (user_id)
    WHERE used_at IS NULL;
