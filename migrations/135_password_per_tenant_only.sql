-- MAPPS-551: password_hash is authoritative on `users` per (email,
-- tenant), never on `identities`. Two portals sharing an email hold
-- two independent passwords forever; every write (setup, forgot,
-- change) lands only on the specific users row and the mirror stops
-- fanning password across the boundary.
--
-- Migration 128 seeded `identities.password_hash` from `users` and
-- kept the two in sync via a bidir trigger; migration 134 (MAPPS-548)
-- added a session-scoped opt-out and a "mirror password_hash only
-- when it actually changed" guard. Both of those were half-measures:
-- the setup path was isolated, but a subsequent change-password or
-- forgot-password reset re-fanned the new hash onto every users row
-- at that email, silently reunifying every portal (and the mokosh
-- super-admin) at the same email under one password.
--
-- This migration retires the password half of the mirror in BOTH
-- directions on UPDATE:
--   - `sync_user_to_identity_and_membership` (users -> identity):
--     the UPDATE branch drops `password_hash` from the mirrored
--     column list. Membership + per-human profile columns still
--     mirror normally.
--   - `sync_identity_to_users` (identity -> users): drops the
--     `password_hash` mirror entirely (was CASE-guarded post-134;
--     now removed outright). Every other column still mirrors.
--
-- INSERT branch of the forward trigger is deliberately KEPT AS IS.
-- A brand-new email creating its first users row still seeds an
-- identity row with the same password_hash; that seed is the initial
-- identity password and stays consistent until the first per-tenant
-- write, at which point identity's copy becomes historical and
-- unused. The MAPPS-548 `app.skip_users_identity_mirror` opt-out
-- stays in place - it still short-circuits the full mirror when
-- callers explicitly set it, which the setup path does out of
-- habit; belt-and-braces against any future column addition that
-- might silently escape.
--
-- Application-level consequence: `AuthService::authenticate_identity_first`
-- can no longer verify against `identities.password_hash`. Post-551
-- it walks the identity's memberships and verifies against each
-- corresponding users row's `password_hash`, treating the set of
-- matching memberships as the effective auto-scope / picker input.
-- That change lands in the same commit as this migration.

CREATE OR REPLACE FUNCTION sync_user_to_identity_and_membership()
RETURNS TRIGGER AS $$
DECLARE
    v_identity_id UUID;
BEGIN
    -- MAPPS-548: opt-out. Still supported for callers that want to
    -- suppress ALL mirror side-effects for one transaction (e.g. a
    -- setup-password write that should not touch any other row).
    -- Default (flag unset) runs the pre-548 mirror MINUS the
    -- MAPPS-551 password redaction below.
    IF current_setting('app.skip_users_identity_mirror', true) = 'on' THEN
        RETURN NEW;
    END IF;

    IF (TG_OP = 'INSERT') THEN
        SELECT id INTO v_identity_id
        FROM identities WHERE lower(email) = lower(NEW.email);

        IF v_identity_id IS NULL THEN
            -- First users row for this email seeds the identity.
            -- password_hash is copied on INSERT so a brand-new
            -- identity has a starting value; subsequent per-tenant
            -- writes do NOT re-mirror it (see UPDATE branch below).
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

            -- MAPPS-551: password_hash is DELIBERATELY OMITTED from
            -- this UPDATE. Every other per-human profile column
            -- still mirrors (identity plane is source of truth for
            -- name, phone, mfa, avatar, timezone, locale, verified
            -- + last-login timestamps, prefs, settings) but a
            -- users-side password change does not propagate through
            -- identities to every other users row at this email.
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
                updated_at = NEW.updated_at
            WHERE id = v_identity_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION sync_identity_to_users()
RETURNS TRIGGER AS $$
BEGIN
    IF current_setting('app.skip_users_identity_mirror', true) = 'on' THEN
        RETURN NEW;
    END IF;

    -- Break the dual-direction cycle. When depth > 1 we're already
    -- inside a users -> identity mirror, so the change originated on
    -- users and there is nothing to write back.
    IF pg_trigger_depth() > 1 THEN
        RETURN NEW;
    END IF;

    -- MAPPS-551: `password_hash` is DELIBERATELY OMITTED. Post-551
    -- identity's password_hash is not authoritative; it should never
    -- overwrite a per-tenant users password. The MAPPS-548 CASE
    -- guard (only-when-changed) is retired outright because even a
    -- deliberate identity password write should not fan out to
    -- users - the operator wants portal A and portal B at the same
    -- email to hold independent passwords, and any identity-side
    -- write would collapse that.
    UPDATE users SET
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
        updated_at = NEW.updated_at
    WHERE lower(email) = lower(NEW.email);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
