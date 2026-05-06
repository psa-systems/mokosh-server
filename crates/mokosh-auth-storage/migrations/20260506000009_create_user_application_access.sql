-- Per-(user, client) entitlement.
--
-- A user must have an entitlement row for a given client before the
-- authorize endpoint will mint tokens for them. In phase 1 the engine
-- JIT-creates these rows on first use (any user with an active session
-- is implicitly entitled to any platform-wide client). This table exists
-- so that a future admin UI can manage entitlements explicitly: revoke a
-- user's access to one app without disabling their account, narrow the
-- scope set granted to a specific client, audit which apps a user has
-- ever logged into.

CREATE TABLE mokosh_auth.user_application_access (
    user_id         UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE CASCADE,
    client_id       UUID         NOT NULL REFERENCES mokosh_auth.oauth_clients(client_id) ON DELETE CASCADE,
    tenant_id       UUID         NOT NULL,
    granted_scopes  TEXT[]       NOT NULL,
    granted_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    granted_by      UUID         REFERENCES mokosh_auth.users(id) ON DELETE SET NULL,
    revoked_at      TIMESTAMPTZ,
    revoke_reason   TEXT,

    PRIMARY KEY (user_id, client_id)
);

CREATE INDEX user_app_access_client_idx
    ON mokosh_auth.user_application_access (client_id)
    WHERE revoked_at IS NULL;
