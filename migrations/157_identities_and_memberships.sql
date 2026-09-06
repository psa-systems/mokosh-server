-- MAPPS-475 (MAPPS-474 phase 1): identities + tenant_memberships.
--
-- Foundation for Cloudflare-style multi-tenant users. One human = one
-- `identities` row (email + password + MFA + profile). One seat in a tenant
-- = one `tenant_memberships` row (identity_id + tenant_id + role + status).
--
-- Phase 1 is additive scaffolding only. Legacy `users` writes keep working
-- unchanged; a trigger installed at the bottom mirrors every INSERT/UPDATE
-- into the new tables so subsequent phases can start reading from them
-- without a flag-day rewrite of the 76 existing `user.tenant_id` callsites.
--
-- RLS: neither table is RLS-enabled. Both are cross-tenant lookup tables
-- read during pre-auth resolution (login-by-email needs the identity row
-- before any GUC is set). Same rationale as
-- `tenant_membership_entitlements` (125): auth middleware runs these
-- reads on the migrator pool with no tenant GUC, and the write surface is
-- gated to the auth service.
--
-- See docs/mokosh-identity/design.md for the full plan.

-- ============================================================================
-- IDENTITIES: the human
-- ============================================================================

CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone VARCHAR(50),
    mobile VARCHAR(50),
    avatar_url VARCHAR(500),
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    locale VARCHAR(10) NOT NULL DEFAULT 'en-US',
    email_verified_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(100),
    notification_preferences JSONB NOT NULL DEFAULT '{}',
    settings JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_identities_email_lower ON identities (lower(email));

CREATE TRIGGER identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- TENANT_MEMBERSHIPS: the seat
-- ============================================================================

CREATE TABLE tenant_memberships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'technician'
        CHECK (role IN ('super_admin', 'admin', 'manager', 'technician', 'dispatcher', 'sales', 'finance')),
    title VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive', 'pending')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (identity_id, tenant_id)
);

CREATE INDEX idx_tenant_memberships_tenant_role
    ON tenant_memberships (tenant_id, role) WHERE status = 'active';

CREATE INDEX idx_tenant_memberships_identity
    ON tenant_memberships (identity_id) WHERE status = 'active';

CREATE TRIGGER tenant_memberships_updated_at
    BEFORE UPDATE ON tenant_memberships
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- BACKFILL from users
-- ============================================================================
--
-- `DISTINCT ON (lower(email))` collapses multi-tenant email collisions to
-- one identity per email, picking the earliest-created users row's
-- per-human fields as the winner. Later collisions become additional
-- memberships pointing at the winner. Downstream policy (documented in
-- the epic): affected operators reset their password on next login.
--
-- `status = 'pending'` on `users` is not a valid `identities.status` value
-- (identities are person-level; 'pending' belongs on the membership only).
-- Map 'pending' -> 'active' on identity, keep on membership.

INSERT INTO identities (
    id, email, password_hash, first_name, last_name, phone, mobile,
    avatar_url, timezone, locale, email_verified_at, last_login_at,
    mfa_enabled, mfa_secret, notification_preferences, settings, status,
    created_at, updated_at
)
SELECT DISTINCT ON (lower(email))
    id, email, password_hash, first_name, last_name, phone, mobile,
    avatar_url, timezone, locale, email_verified_at, last_login_at,
    mfa_enabled, mfa_secret, notification_preferences, settings,
    CASE WHEN status = 'pending' THEN 'active' ELSE status END,
    created_at, updated_at
FROM users
ORDER BY lower(email), created_at ASC;

INSERT INTO tenant_memberships (
    identity_id, tenant_id, role, title, status,
    joined_at, created_at, updated_at
)
SELECT
    (SELECT id FROM identities WHERE lower(email) = lower(u.email)),
    u.tenant_id, u.role, u.title, u.status,
    u.created_at, u.created_at, u.updated_at
FROM users u;

-- ============================================================================
-- DUAL-WRITE TRIGGER on users
-- ============================================================================
--
-- Phases 2..5 land new endpoints that READ from identities + memberships;
-- legacy code paths keep WRITING to `users` unchanged. This trigger
-- guarantees that every legacy write leaves identity + membership
-- coherent so the two data planes never drift. Phase 6 drops the dead
-- per-human columns from `users` and retires this trigger.
--
-- AFTER-row form: `users.id` and defaults are stable at this point, and
-- we need the caller's inserted PK to become the identity id when the
-- email is new.

CREATE OR REPLACE FUNCTION sync_user_to_identity_and_membership()
RETURNS TRIGGER AS $$
DECLARE
    v_identity_id UUID;
BEGIN
    IF (TG_OP = 'INSERT') THEN
        SELECT id INTO v_identity_id
        FROM identities WHERE lower(email) = lower(NEW.email);

        IF v_identity_id IS NULL THEN
            INSERT INTO identities (
                id, email, password_hash, first_name, last_name, phone, mobile,
                avatar_url, timezone, locale, email_verified_at, last_login_at,
                mfa_enabled, mfa_secret, notification_preferences, settings, status,
                created_at, updated_at
            ) VALUES (
                NEW.id, NEW.email, NEW.password_hash, NEW.first_name, NEW.last_name,
                NEW.phone, NEW.mobile, NEW.avatar_url, NEW.timezone, NEW.locale,
                NEW.email_verified_at, NEW.last_login_at, NEW.mfa_enabled, NEW.mfa_secret,
                NEW.notification_preferences, NEW.settings,
                CASE WHEN NEW.status = 'pending' THEN 'active' ELSE NEW.status END,
                NEW.created_at, NEW.updated_at
            )
            RETURNING id INTO v_identity_id;
        END IF;

        INSERT INTO tenant_memberships (
            identity_id, tenant_id, role, title, status,
            joined_at, created_at, updated_at
        ) VALUES (
            v_identity_id, NEW.tenant_id, NEW.role, NEW.title, NEW.status,
            NEW.created_at, NEW.created_at, NEW.updated_at
        )
        ON CONFLICT (identity_id, tenant_id) DO UPDATE
            SET role = EXCLUDED.role,
                title = EXCLUDED.title,
                status = EXCLUDED.status,
                updated_at = EXCLUDED.updated_at;

    ELSIF (TG_OP = 'UPDATE') THEN
        SELECT id INTO v_identity_id
        FROM identities WHERE lower(email) = lower(NEW.email);

        IF v_identity_id IS NOT NULL THEN
            UPDATE tenant_memberships SET
                role = NEW.role,
                title = NEW.title,
                status = NEW.status,
                updated_at = NEW.updated_at
            WHERE identity_id = v_identity_id AND tenant_id = NEW.tenant_id;

            -- Per-human profile changes (name, phone, mfa, etc) also
            -- propagate so the identity plane keeps pace with legacy
            -- edits until phase 6 makes identities the sole writer.
            UPDATE identities SET
                first_name = NEW.first_name,
                last_name = NEW.last_name,
                phone = NEW.phone,
                mobile = NEW.mobile,
                avatar_url = NEW.avatar_url,
                timezone = NEW.timezone,
                locale = NEW.locale,
                email_verified_at = NEW.email_verified_at,
                last_login_at = NEW.last_login_at,
                mfa_enabled = NEW.mfa_enabled,
                mfa_secret = NEW.mfa_secret,
                notification_preferences = NEW.notification_preferences,
                settings = NEW.settings,
                -- password_hash intentionally mirrored: legacy
                -- password-change endpoint still writes to users, and
                -- identity-plane readers need the new hash.
                password_hash = NEW.password_hash,
                updated_at = NEW.updated_at
            WHERE id = v_identity_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_sync_to_identity
    AFTER INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION sync_user_to_identity_and_membership();
