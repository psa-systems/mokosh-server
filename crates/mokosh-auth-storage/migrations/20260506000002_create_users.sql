-- Auth users. Distinct from any PSA-domain "users" table; the PSA tables
-- reference these by id via the `tenant_id, user_id` pair.

CREATE TABLE mokosh_auth.users (
    id                UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID         NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    email             CITEXT       NOT NULL,
    email_verified_at TIMESTAMPTZ,
    -- Argon2id PHC string. NULL means "passwordless" (federated only).
    password_hash     TEXT,
    role              TEXT         NOT NULL DEFAULT 'member',
    status            TEXT         NOT NULL DEFAULT 'pending',
    first_name        TEXT,
    last_name         TEXT,
    timezone          TEXT         NOT NULL DEFAULT 'UTC',
    locale            TEXT         NOT NULL DEFAULT 'en-US',
    mfa_enrolled      BOOLEAN      NOT NULL DEFAULT FALSE,
    last_login_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at        TIMESTAMPTZ,

    CONSTRAINT users_role_chk
        CHECK (role IN ('admin', 'manager', 'finance', 'member', 'readonly')),
    CONSTRAINT users_status_chk
        CHECK (status IN ('pending', 'active', 'suspended', 'deleted'))
);

-- Email is unique within a tenant, not globally. This means the same
-- person can have a separate account in two tenants without collision.
CREATE UNIQUE INDEX users_tenant_email_idx
    ON mokosh_auth.users (tenant_id, email)
    WHERE deleted_at IS NULL;

-- Lookups by email across tenants (federation home-realm discovery, admin
-- search) hit this partial index.
CREATE INDEX users_email_active_idx
    ON mokosh_auth.users (email)
    WHERE deleted_at IS NULL;

CREATE INDEX users_tenant_status_idx
    ON mokosh_auth.users (tenant_id, status)
    WHERE deleted_at IS NULL;
