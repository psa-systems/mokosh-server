-- PMS-244: Mokosh-owned org membership. A tenant admin invites a person by
-- email; on that person's next Bunyip login the invite resolves them into the
-- tenant (acceptance is login-driven, see auth::middleware). Orgs live here,
-- not in Bunyip (which is a personal-subscription IdP with no org concept).

CREATE TABLE tenant_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'technician'
        CHECK (role IN ('admin', 'manager', 'technician', 'dispatcher', 'sales', 'finance')),
    invited_by UUID REFERENCES users(id),
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'revoked')),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- At most one live invite per (tenant, email). Case-insensitive: emails are
-- stored lowercased but the index defends against any caller that forgets.
CREATE UNIQUE INDEX idx_tenant_invitations_pending
    ON tenant_invitations (tenant_id, lower(email))
    WHERE status = 'pending';

-- Login resolution looks up the newest pending invite for an email across
-- tenants (PMS-244 phase 2), so index the email of live invites.
CREATE INDEX idx_tenant_invitations_email_pending
    ON tenant_invitations (lower(email))
    WHERE status = 'pending';
