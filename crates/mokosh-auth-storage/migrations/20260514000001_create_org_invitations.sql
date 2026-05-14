-- Org-scoped invitations. Distinct from mokosh_auth.admin_invites
-- (which mint a fresh User during sign-up): these add an EXISTING user
-- as a member of an org tenant. Issued by an org owner/admin, accepted
-- by the invitee while signed in.
--
-- See docs/mokosh-fixes/03-organizations.md.

CREATE TABLE mokosh_auth.org_invitations (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID         NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    email           TEXT         NOT NULL,
    org_role        TEXT         NOT NULL CHECK (org_role IN ('owner', 'admin', 'member')),
    token_hash      BYTEA        NOT NULL UNIQUE,
    issued_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ  NOT NULL,
    accepted_at     TIMESTAMPTZ,
    accepted_by     UUID         REFERENCES mokosh_auth.users(id),
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID         REFERENCES mokosh_auth.users(id),
    invited_by      UUID         NOT NULL REFERENCES mokosh_auth.users(id),
    note            TEXT
);

-- Partial unique: only one OPEN invite per (tenant, email). Resends
-- reuse the existing row.
CREATE UNIQUE INDEX idx_org_invitations_open_unique
    ON mokosh_auth.org_invitations (tenant_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX idx_org_invitations_tenant_open
    ON mokosh_auth.org_invitations (tenant_id, issued_at DESC)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
