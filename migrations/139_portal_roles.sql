-- MAPPS-XXX (mokosh-contact-login prompt 002): MSP-defined RBAC roles
-- for contact-portal access.
--
-- Each MSP tenant carries a set of named roles (e.g. "Billing Contact",
-- "Support Contact", custom "Consultant"). Each role holds a
-- capability set as TEXT[] of stable string constants (see
-- src/modules/contact_portal/capabilities.rs); a contact's effective
-- capabilities are the UNION of every role assigned to them (through
-- `contact_role_assignments`, migration 140). The contact's JWT `caps`
-- claim carries the union so every gated route can check membership
-- without a DB read on the hot path; the server ALSO re-loads the
-- capabilities per-request on privileged mutations so a role revoke
-- lands within the next request tick (see prompt 008).
--
-- `is_builtin` marks the three seeded defaults (Billing Contact,
-- Support Contact, Read-Only) so the MSP admin UI can render them
-- read-only-on-delete + refuse to delete-then-recreate a name
-- collision. Custom roles land with `is_builtin = FALSE`.
CREATE TABLE portal_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(80) NOT NULL,
    capabilities TEXT[] NOT NULL DEFAULT '{}',
    is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_portal_roles_tenant ON portal_roles (tenant_id);

-- Row-level security: the fail-closed `tenant_isolation` policy that
-- the DO-loops in 024/038 attach to every existing table doesn't cover
-- rows created after them, so attach the same shape explicitly here.
-- FORCE so the app pool (NOBYPASSRLS) cannot escape it.
ALTER TABLE portal_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON portal_roles
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
