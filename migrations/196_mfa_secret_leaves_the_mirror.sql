-- PMS-1055: `mfa_secret` leaves both directions of the users <-> identities
-- mirror, and `identities.mfa_secret` is widened to TEXT to hold the same
-- ciphertext `users.mfa_secret` has held since PMS-871 (migration 129).
--
-- Migration 164 (MAPPS-551) already took `password_hash` out of both mirror
-- directions on UPDATE. The argument it made applies unchanged to any secret,
-- and `mfa_secret` is the one it did not cover:
--
--   - `sync_identity_to_users` copied `mfa_secret` back on ANY update to an
--     identity row. `IdentityRepo::record_identity_mfa_success` stamps
--     `identities.mfa_last_totp_step` on every successful identity-plane TOTP
--     verification, so that stamp - a write with nothing to do with the secret -
--     copied the identity's value over the users row. With the users row sealed
--     (PMS-871) and the identity row still holding a pre-871 plaintext secret,
--     the stamp silently turned an encrypted secret back into a plaintext one,
--     with no error and nothing in a log. Confirmed against a real database:
--     enrol over HTTP (both planes sealed), set the identity plane back to
--     plaintext, then `UPDATE identities SET mfa_last_totp_step = 424242` -
--     `users.mfa_secret` comes back the 32-character base32 secret.
--   - `sync_user_to_identity_and_membership` is the same defect with the planes
--     swapped: a users row still legacy after PMS-871 fans its plaintext onto a
--     sealed identity row on any unrelated users UPDATE.
--
-- Both are removed rather than made conditional. A trigger that can convert a
-- sealed secret to a plaintext one is a security regression whether or not it
-- fires today, and "only mirror when it changed" was already tried for
-- `password_hash` (migration 134) and retired as a half-measure in 164.
--
-- The application owns both planes instead, in one transaction per write and
-- with ONE sealed value written to both: `AuthService::start_mfa_enrollment`
-- (enrolment), `upgrade_legacy_mfa_secret` (the pre-871 in-place upgrade, on
-- either login path) and `disable_mfa` (clearing it). `mfa_enabled` and the
-- rest of the per-human profile columns still mirror normally - only the
-- secret leaves.
--
-- The INSERT branch of the forward trigger is deliberately KEPT AS IS, exactly
-- as 164 kept `password_hash` there. It runs only when a users row for a new
-- email finds no identity, so it seeds a brand-new identity row and cannot
-- overwrite anything; whatever the users row holds at that instant is the same
-- value both planes should start from.
--
-- `identities.mfa_secret` was declared `VARCHAR(100)` by migration 157, sized
-- for the 32-character base32 secret. It now holds the same AES-256-GCM
-- base64 value the users plane does (80 characters today), so it gets the same
-- treatment migration 129 gave `users.mfa_secret`: TEXT costs nothing per row
-- in Postgres and a pinned width can only fail a write the day the secret or
-- the AEAD changes. No data change - a migration has no `ENCRYPTION_KEY`, so
-- rows still holding a pre-871 plaintext secret are upgraded in place by
-- `AuthService` on the next successful verification, on either plane.

ALTER TABLE identities
    ALTER COLUMN mfa_secret TYPE TEXT;

CREATE OR REPLACE FUNCTION sync_user_to_identity_and_membership()
RETURNS TRIGGER AS $$
DECLARE
    v_identity_id UUID;
BEGIN
    -- MAPPS-548: opt-out. Still supported for callers that want to
    -- suppress ALL mirror side-effects for one transaction (e.g. a
    -- setup-password write that should not touch any other row).
    IF current_setting('app.skip_users_identity_mirror', true) = 'on' THEN
        RETURN NEW;
    END IF;

    IF (TG_OP = 'INSERT') THEN
        SELECT id INTO v_identity_id
        FROM identities WHERE lower(email) = lower(NEW.email);

        IF v_identity_id IS NULL THEN
            -- First users row for this email seeds the identity.
            -- password_hash (MAPPS-551) and mfa_secret (PMS-1055) are
            -- copied on INSERT because this branch CREATES the identity
            -- row and so cannot overwrite either; subsequent writes to
            -- both columns are the application's own (see UPDATE below).
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

            -- MAPPS-551: `password_hash` is DELIBERATELY OMITTED (a
            -- users-side password change must not fan out to every
            -- users row at this email).
            -- PMS-1055: `mfa_secret` is DELIBERATELY OMITTED for the
            -- same class of reason. Every other per-human profile
            -- column, `mfa_enabled` included, still mirrors.
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

    -- MAPPS-551: `password_hash` is DELIBERATELY OMITTED.
    -- PMS-1055: `mfa_secret` is DELIBERATELY OMITTED. This is the
    -- direction the TOTP watermark stamp fires in, so while it was
    -- here every successful identity-plane verification rewrote the
    -- users-plane secret with whatever the identity plane happened to
    -- hold.
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
        notification_preferences = NEW.notification_preferences,
        settings = NEW.settings,
        updated_at = NEW.updated_at
    WHERE lower(email) = lower(NEW.email);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
