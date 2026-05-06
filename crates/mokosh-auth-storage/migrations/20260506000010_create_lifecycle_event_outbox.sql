-- Outbox for back-channel logout tokens (OIDC Back-Channel Logout 1.0)
-- and lifecycle events (user.suspended, user.deleted,
-- entitlement.granted, entitlement.revoked).
--
-- When the OP needs to notify a relying party of state change, it writes
-- a row here. A worker drains the outbox, signs a JWT, POSTs it to the
-- client's `backchannel_logout_uri` or `lifecycle_event_uri`, and updates
-- delivered_at on success.

CREATE TABLE mokosh_auth.lifecycle_event_outbox (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type      TEXT         NOT NULL,
    user_id         UUID         REFERENCES mokosh_auth.users(id) ON DELETE SET NULL,
    -- NULL = broadcast to every client that has an active session for the
    -- subject user; set = deliver only to this one client.
    client_id       UUID         REFERENCES mokosh_auth.oauth_clients(client_id) ON DELETE SET NULL,
    tenant_id       UUID         NOT NULL,
    payload         JSONB        NOT NULL DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    available_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- Exponential backoff on delivery failures.
    attempts        INTEGER      NOT NULL DEFAULT 0,
    last_error      TEXT,
    delivered_at    TIMESTAMPTZ,

    CONSTRAINT lifecycle_event_type_chk
        CHECK (event_type IN (
            'backchannel_logout',
            'user.suspended',
            'user.unsuspended',
            'user.deleted',
            'entitlement.granted',
            'entitlement.revoked'
        ))
);

-- Worker query: pending events ready to send, oldest first.
CREATE INDEX lifecycle_outbox_pending_idx
    ON mokosh_auth.lifecycle_event_outbox (available_at)
    WHERE delivered_at IS NULL;
