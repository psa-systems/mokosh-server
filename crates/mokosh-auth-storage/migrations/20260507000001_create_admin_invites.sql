-- Admin-issued invites for onboarding new MSP employees.
--
-- An admin (super_admin or admin) creates an invite by POSTing to
-- /v1/auth/invites with an email + role. The server stores the SHA-256
-- hash of a fresh 32-byte CSPRNG token, emails the raw token to the
-- recipient, and the recipient accepts within `expires_at` by POSTing
-- to /v1/auth/invites/by-token/<token>/accept with their chosen
-- password.
--
-- Single use: `used_at` is set the moment the accept transaction
-- commits. Replay is impossible.
--
-- Revocation: an admin can mark an outstanding invite revoked at any
-- time. `revoked_at` is non-NULL once revoked; the accept endpoint
-- treats revoked invites the same as expired or used (collapsed 404 at
-- the HTTP layer for enumeration resistance).

CREATE TABLE mokosh_auth.admin_invites (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID         NOT NULL,
    email           CITEXT       NOT NULL,
    role            TEXT         NOT NULL,
    -- SHA-256 of the raw token. Raw value is emailed to the recipient
    -- exactly once and never persisted.
    token_hash      BYTEA        NOT NULL UNIQUE,
    invited_by      UUID         NOT NULL REFERENCES mokosh_auth.users(id) ON DELETE RESTRICT,
    issued_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ  NOT NULL,
    -- Set when the recipient successfully accepts the invite.
    used_at         TIMESTAMPTZ,
    used_by         UUID         REFERENCES mokosh_auth.users(id) ON DELETE SET NULL,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID         REFERENCES mokosh_auth.users(id) ON DELETE SET NULL,
    revoke_reason   TEXT,
    -- Optional payload the admin attaches at issue time, surfaced on
    -- the accept page. Plain text; render with HTML escaping.
    note            TEXT,

    CONSTRAINT admin_invites_role_chk
        CHECK (role IN ('admin', 'manager', 'finance', 'member', 'readonly')),
    CONSTRAINT admin_invites_token_hash_len_chk
        CHECK (octet_length(token_hash) = 32),
    -- Mutually-exclusive terminal states. The accept transaction sets
    -- used_at while holding the row lock; revoke is rejected once
    -- used_at is non-NULL.
    CONSTRAINT admin_invites_terminal_state_chk
        CHECK (NOT (used_at IS NOT NULL AND revoked_at IS NOT NULL)),
    -- Bootstrapping a new super_admin via an emailed link is too much
    -- trust for the recipient's mailbox in this threat model. Promoting
    -- an existing user is a separate operation, out of scope here.
    CONSTRAINT admin_invites_no_super_admin_chk
        CHECK (role <> 'super_admin')
);

-- One outstanding invite per (tenant, email). Re-issuing is an explicit
-- "resend" or "revoke + reissue" path. Many *historical* invites for
-- the same email are allowed; only one open at a time.
CREATE UNIQUE INDEX admin_invites_open_idx
    ON mokosh_auth.admin_invites (tenant_id, email)
    WHERE used_at IS NULL AND revoked_at IS NULL;

-- Cleanup: cron-driven deletion of fully-resolved invites.
CREATE INDEX admin_invites_terminal_idx
    ON mokosh_auth.admin_invites (issued_at)
    WHERE used_at IS NOT NULL OR revoked_at IS NOT NULL;

-- Admin UI: list pending invites a given admin issued.
CREATE INDEX admin_invites_invited_by_idx
    ON mokosh_auth.admin_invites (invited_by)
    WHERE used_at IS NULL AND revoked_at IS NULL;
