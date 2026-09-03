-- MAPPS-XXX (mokosh-contact-login prompt 002): many-to-many contact ->
-- portal role.
--
-- One contact can hold multiple roles (a "Billing" contact who also
-- raises tickets = Billing Contact + Support Contact). Effective
-- capabilities = union across every assigned role's capability set
-- (see portal_roles.capabilities). The staff-side grant flow
-- (`ContactService::grant_portal_access` in prompt 003) rewrites
-- this table atomically per contact: the new role_ids REPLACE any
-- prior set for that contact rather than merging.
--
-- Cascade on both sides so cleaning up a role (`DELETE FROM
-- portal_roles`) or a contact (`DELETE FROM contacts`) drops the
-- membership row without leaving orphans.
CREATE TABLE contact_role_assignments (
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES portal_roles(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (contact_id, role_id)
);
CREATE INDEX idx_contact_role_assignments_contact ON contact_role_assignments (contact_id);
CREATE INDEX idx_contact_role_assignments_role ON contact_role_assignments (role_id);

ALTER TABLE contact_role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_role_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_role_assignments
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
