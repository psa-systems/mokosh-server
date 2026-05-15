-- Short-lived single-use challenges for MFA-gated login + step-up.
--
-- `purpose = 'login'` rows are issued by /v1/auth/login when the user
-- has MFA on. The raw token goes back to the SPA; the SPA POSTs it to
-- /v1/auth/mfa/verify with the user's TOTP or recovery code. On
-- success the row is marked consumed and the OIDC token bundle is
-- issued.
--
-- `purpose = 'step_up'` rows gate destructive operations (regenerate
-- recovery codes, disable MFA) by requiring "MFA verified within the
-- last few minutes." Same single-use shape, separate type so a stolen
-- login challenge cannot be replayed as a step-up token.

CREATE TABLE mokosh_auth.mfa_challenges (
    id                UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id           UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    tenant_id         UUID         NOT NULL,
    token_hash        BYTEA        NOT NULL UNIQUE,
    -- The OIDC client + scope from the original login request (NULL for
    -- the cookie-only login path and for step_up challenges).
    client_id         UUID,
    scope             TEXT[]       NOT NULL DEFAULT '{}',
    -- Same active-tenant resolution as the regular login path.
    active_tenant_id  UUID         NOT NULL,
    purpose           TEXT         NOT NULL CHECK (purpose IN ('login', 'step_up')),
    expires_at        TIMESTAMPTZ  NOT NULL,
    consumed_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    ip                INET,
    user_agent        TEXT,

    CONSTRAINT mfa_challenges_hash_len_chk CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX mfa_challenges_open_by_user_idx
    ON mokosh_auth.mfa_challenges (user_id, purpose)
    WHERE consumed_at IS NULL;
