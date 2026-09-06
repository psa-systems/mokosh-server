-- MAPPS-498 (MAPPS-496 stage 1): bidirectional users <-> identities sync.
--
-- Migration 128 installed `users_sync_to_identity`, an AFTER
-- INSERT/UPDATE trigger on `users` that mirrors writes to
-- `identities` + `tenant_memberships`. It goes only one direction.
--
-- Under MAPPS-496 the plan is to migrate application writers off
-- `users` and onto `identities`. Without a back-mirror, any UPDATE on
-- `identities.<per-human column>` would leave every matching `users`
-- row stale and break any legacy reader still hitting `users`. This
-- migration adds the identity -> users direction so both stages of
-- the reader/writer migration can proceed independently.
--
-- Recursion guard: `pg_trigger_depth()` is the standard Postgres
-- primitive for breaking dual-direction trigger cycles. When the
-- identity -> users trigger fires because a users -> identity trigger
-- just fired (depth 2), skip; the source-of-truth write already
-- happened one hop up. On a direct application UPDATE to `identities`
-- the depth is 1 and the mirror runs normally.
--
-- Multi-membership: a single identity may back many `users` rows
-- (one per tenant they hold a membership in). The UPDATE ... WHERE
-- lower(email) = lower(NEW.email) intentionally covers every one.

CREATE OR REPLACE FUNCTION sync_identity_to_users()
RETURNS TRIGGER AS $$
BEGIN
    -- Break the dual-direction cycle. When depth > 1 we're already
    -- inside a users -> identity mirror, so the change originated on
    -- users and there is nothing to write back.
    IF pg_trigger_depth() > 1 THEN
        RETURN NEW;
    END IF;

    UPDATE users SET
        password_hash = NEW.password_hash,
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

CREATE TRIGGER identities_sync_to_users
    AFTER UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION sync_identity_to_users();
