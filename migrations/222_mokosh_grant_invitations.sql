-- PMS-1208: pending / accept / expire lifecycle for Mokosh grants.
--
-- BUNYIP-673 + BUNYIP-674 shipped grants as active-on-create with no
-- accept step. This table adds the pending-invitation state that
-- Cloudflare's account-membership model uses: an owner invites, an
-- email fires, the grantee clicks accept, and only THEN does the
-- `mokosh_bunyip_grants` mirror row (added in migration 220) get
-- written. A grantee who does not accept in 7 days sees the invite
-- expire; either party can cancel.
--
-- The row lives in the OWNER TENANT (`tenant_id = the account being
-- shared`) so RLS scoping just works and tenant deletion cascades
-- the pending invites. `bunyip_user_id` columns are stored bare (no
-- FK to `users`) because in SaaS mode the invitee may not have a
-- Mokosh users row until acceptance - this is the same pattern
-- `mokosh_bunyip_grants` already uses on both sides of the (grantee,
-- account) pair.
--
-- `invitee_email` is captured for the owner's outbox display and
-- for the grantee's mailer target; in standalone mode where there is
-- no bunyip identity plane, the email is the only join key at
-- invite-creation time.
--
-- `accept_token_hash` is Argon2 (matching `portal_setup_tokens`,
-- PMS-136 shape); the plaintext token rides in the email link and
-- is verified by the accept handler and then never touched again.
--
-- The partial UNIQUE index enforces one PENDING invite per
-- (tenant, invitee) - a second invite to the same email in the same
-- tenant while an earlier one is still pending returns 409. Multiple
-- rows for the same triple in different terminal states (declined,
-- expired, canceled) are the audit trail; a re-invite after decline
-- inserts a new pending row alongside the historical one.

CREATE TABLE mokosh_grant_invitations (
    id                     UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id              UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    inviter_bunyip_user_id UUID         NOT NULL,
    invitee_bunyip_user_id UUID,
    invitee_email          VARCHAR(255) NOT NULL,
    role                   VARCHAR(50)  NOT NULL,
    accept_token_hash      VARCHAR(255) NOT NULL,
    status                 VARCHAR(20)  NOT NULL DEFAULT 'pending',
    invited_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at             TIMESTAMPTZ  NOT NULL,
    accepted_at            TIMESTAMPTZ,
    declined_at            TIMESTAMPTZ,
    canceled_at            TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CHECK (status IN ('pending', 'accepted', 'declined', 'canceled', 'expired')),
    CHECK (role IN ('admin', 'manager', 'technician', 'finance', 'read_only')),
    -- An owner cannot invite themselves; the CHECK guards the id-based
    -- path when `invitee_bunyip_user_id` is known at invite time. The
    -- email-only path (standalone mode with no bunyip identity yet)
    -- is guarded in the service layer against the inviter's own
    -- verified address.
    CHECK (
        invitee_bunyip_user_id IS NULL
        OR invitee_bunyip_user_id <> inviter_bunyip_user_id
    ),
    -- The coupling that keeps the terminal-state columns honest: an
    -- accepted invite HAS `accepted_at` and no `declined_at`, and so
    -- on. Prevents a webhook or a hand-crafted UPDATE from writing a
    -- row that reads as "accepted but also canceled".
    CHECK (
        (status = 'pending'  AND accepted_at IS NULL AND declined_at IS NULL AND canceled_at IS NULL)
     OR (status = 'accepted' AND accepted_at IS NOT NULL AND declined_at IS NULL AND canceled_at IS NULL)
     OR (status = 'declined' AND declined_at IS NOT NULL AND accepted_at IS NULL AND canceled_at IS NULL)
     OR (status = 'canceled' AND canceled_at IS NOT NULL AND accepted_at IS NULL AND declined_at IS NULL)
     OR (status = 'expired'  AND accepted_at IS NULL AND declined_at IS NULL AND canceled_at IS NULL)
    )
);

-- One pending invite per (tenant, invitee_email). Case-insensitive so
-- "Alice@Example.com" and "alice@example.com" collide, matching the
-- `tenant_invitations.email` shape PMS's existing invite flow uses.
-- The invitee is identified by email here (not by bunyip user id)
-- because standalone mode has no bunyip user id at invite time; the
-- SaaS-mode resolver fills `invitee_bunyip_user_id` alongside.
CREATE UNIQUE INDEX idx_grant_invitations_pending_email
    ON mokosh_grant_invitations (tenant_id, lower(invitee_email))
    WHERE status = 'pending';

CREATE INDEX idx_grant_invitations_by_invitee
    ON mokosh_grant_invitations (invitee_bunyip_user_id)
    WHERE status = 'pending' AND invitee_bunyip_user_id IS NOT NULL;

-- The expiry sweep's index: a partial on `expires_at` where the row
-- is still pending, so the hourly job's SELECT is a range scan over
-- a small set instead of a full table scan.
CREATE INDEX idx_grant_invitations_expiry
    ON mokosh_grant_invitations (expires_at)
    WHERE status = 'pending';

-- Tenant-scoped read patterns (owner outbox).
CREATE INDEX idx_grant_invitations_by_tenant
    ON mokosh_grant_invitations (tenant_id, status, invited_at DESC);

COMMENT ON TABLE mokosh_grant_invitations IS
    'PMS-1208: pending grant invitations. The `mokosh_bunyip_grants` mirror (BUNYIP-674) becomes authoritative only after acceptance; before that this row is the whole state.';
COMMENT ON COLUMN mokosh_grant_invitations.accept_token_hash IS
    'Argon2 hash of the accept token; the plaintext rides in the invitation email link and is verified by the accept handler.';
COMMENT ON COLUMN mokosh_grant_invitations.status IS
    'pending | accepted | declined | canceled | expired. Terminal-state columns (`accepted_at` / `declined_at` / `canceled_at`) are pinned to the status by a CHECK constraint.';
