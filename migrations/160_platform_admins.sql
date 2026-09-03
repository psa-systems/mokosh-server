-- MAPPS-513 (MAPPS-474 stage A follow-up): platform super-admin split.
--
-- The identity model established by MAPPS-474 conflates the mokosh
-- platform super-admin (cross-cutting, no tenant) with tenant admins
-- (bound to one tenant via memberships). Both share the identity plane
-- keyed by email, so when the two personas share an email in dev/prod,
-- setting a password for one clobbers the other via the MAPPS-498 mirror.
--
-- This migration adds `platform_admins`, a dedicated credential store
-- for the platform super-admin persona. No tenant_id, no memberships;
-- one row per platform operator. Backfill from `users WHERE role =
-- 'super_admin'` in migration 132 preserves current credentials.
--
-- Stage A leaves the existing `users.role = 'super_admin'` intact for
-- compat with every `RequireSuperAdmin` extractor. Super-admins can log
-- in via either path; the new /platform/login is the independent one
-- that will not be affected by tenant-admin password resets.
--
-- RLS-exempt (like `identities`): cross-cutting lookup on the pre-auth
-- login path, small write surface owned by the platform service.

CREATE TABLE platform_admins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    locale VARCHAR(10) NOT NULL DEFAULT 'en-US',
    email_verified_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(100),
    mfa_last_totp_step BIGINT NOT NULL DEFAULT 0,
    notification_preferences JSONB NOT NULL DEFAULT '{}',
    settings JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_platform_admins_email_lower
    ON platform_admins (lower(email));

CREATE TRIGGER platform_admins_updated_at
    BEFORE UPDATE ON platform_admins
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
