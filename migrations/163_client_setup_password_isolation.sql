-- MAPPS-548: teach the MAPPS-498 users<->identities mirror to short-circuit
-- when a session-scoped flag says "this write is a client-admin setup
-- password; do NOT propagate to shared identity/users rows."
--
-- The mirror's normal behavior (users write -> identities write ->
-- every-users-row-with-this-email write) is the whole point of the
-- identity plane and stays the default. Only the specific tenant-admin
-- welcome-email setup path (see `AuthService::reset_password`) flips
-- the flag to prevent a NEW client-admin's first-ever password write
-- from overwriting a pre-existing account's password (mokosh
-- super-admin, tenant admin in another tenant, another client's admin
-- who happens to share the same email).
--
-- Mechanism: session-scoped GUC `app.skip_users_identity_mirror`.
-- `current_setting(name, true)` returns NULL when unset, which
-- collapses to the default not-skipping branch. Callers set it via
-- `SET LOCAL` inside a transaction so the flag scope is exactly the
-- transaction that owns the setup write; it evaporates on COMMIT /
-- ROLLBACK, so a caller that forgets to unset does not leak the flag
-- into another request handled by the same pool connection.
--
-- Both triggers gate on the SAME flag. In-flight writes chain
-- through the mirror in either direction, so either endpoint of the
-- cycle has to short-circuit; picking one and leaving the other
-- would let a users write still update identities, which would then
-- fall through to the untrapped identity->users direction on the
-- next depth.
--
-- Existing `pg_trigger_depth() > 1` recursion guard on the
-- identity->users side (migration 130) stays intact; this migration
-- adds a second early-return above it. `sync_user_to_identity_and_membership`
-- has no recursion guard today (users writes always kick off the
-- chain), so the new check goes right at the top of the function.

CREATE OR REPLACE FUNCTION sync_user_to_identity_and_membership()
RETURNS TRIGGER AS $$
DECLARE
    v_identity_id UUID;
BEGIN
    -- MAPPS-548: opt-out. When a client-admin setup-password
    -- transaction sets `app.skip_users_identity_mirror = 'on'`, the
    -- new users row's password_hash write must NOT propagate to
    -- identities (which would then re-mirror to every other users
    -- row at this email). Default (flag unset / any other value)
    -- keeps the pre-548 behavior.
    IF current_setting('app.skip_users_identity_mirror', true) = 'on' THEN
        RETURN NEW;
    END IF;

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

CREATE OR REPLACE FUNCTION sync_identity_to_users()
RETURNS TRIGGER AS $$
BEGIN
    -- MAPPS-548: symmetric opt-out on the reverse mirror. If the
    -- setup-password transaction ever wrote to identities directly
    -- (it does not today, but a future refactor might), the reverse
    -- update to every-users-row-at-this-email must also short-circuit
    -- so an unrelated pre-existing account's password is not
    -- clobbered. Default preserves pre-548 behavior.
    IF current_setting('app.skip_users_identity_mirror', true) = 'on' THEN
        RETURN NEW;
    END IF;

    -- Break the dual-direction cycle. When depth > 1 we're already
    -- inside a users -> identity mirror, so the change originated on
    -- users and there is nothing to write back.
    IF pg_trigger_depth() > 1 THEN
        RETURN NEW;
    END IF;

    -- MAPPS-548: the pre-548 trigger blindly mirrored EVERY per-human
    -- column on every identity UPDATE, including password_hash. That
    -- meant any UPDATE to identities that changed only a non-password
    -- field (e.g. `update_last_login` writing `last_login_at`) still
    -- overwrote every matching users row's password_hash with the
    -- identity's current value. In a multi-account collision (mokosh
    -- super-admin + tenant admin in another tenant + a fresh
    -- client-admin at the same email), the client-admin's isolated
    -- setup write would land, but the very next login for a
    -- DIFFERENT account would fire `update_last_login`, fire this
    -- trigger, and clobber the client-admin's fresh hash back to the
    -- earlier account's hash. Cause of the MAPPS-548 walkthrough
    -- failure ("client-c hash == account1 hash? true" post-setup).
    --
    -- Fix: mirror password_hash ONLY when NEW.password_hash IS
    -- DISTINCT FROM OLD.password_hash. Everything else (name, phone,
    -- avatar, timezone, locale, verified/last-login timestamps, MFA
    -- state, prefs, settings) stays blind-mirrored: those columns
    -- are per-human and the identity plane is their source of truth,
    -- so overwriting a users row with a stale-but-current identity
    -- value is correct. Password is the sensitive exception because
    -- MAPPS-548 explicitly wants collision-safe writes.
    UPDATE users SET
        password_hash = CASE
            WHEN NEW.password_hash IS DISTINCT FROM OLD.password_hash
                THEN NEW.password_hash
            ELSE users.password_hash
        END,
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
