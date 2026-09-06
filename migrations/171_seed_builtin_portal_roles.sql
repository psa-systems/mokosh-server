-- MAPPS-XXX (mokosh-contact-login prompt 002): built-in portal roles
-- for every existing tenant.
--
-- Three defaults land automatically:
--   Billing Contact -> can pay invoices + accept quotes + manage own
--                      profile + read notifications.
--   Support Contact -> can raise + comment tickets + read KB.
--   Read-Only       -> every *:read capability across the domain.
--
-- Idempotent via ON CONFLICT (tenant_id, name). A tenant provisioned
-- AFTER this migration gets the same three rows inserted by
-- `TenantService::create_tenant` (see the code change in prompt 002),
-- so no matter which path a tenant took, its role list starts here.
--
-- The MSP admin can extend or edit these via
-- `PortalRoleService::update_role` (prompt 007); the built-in flag
-- allows renaming but not deletion.
INSERT INTO portal_roles (tenant_id, name, capabilities, is_builtin)
SELECT t.id, 'Billing Contact',
       ARRAY['invoices:read', 'invoices:pay', 'quotes:read', 'quotes:accept',
             'notifications:read', 'settings:manage_own'],
       TRUE
FROM tenants t
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO portal_roles (tenant_id, name, capabilities, is_builtin)
SELECT t.id, 'Support Contact',
       ARRAY['tickets:read', 'tickets:write', 'tickets:comment', 'kb:read',
             'notifications:read', 'settings:manage_own'],
       TRUE
FROM tenants t
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO portal_roles (tenant_id, name, capabilities, is_builtin)
SELECT t.id, 'Read-Only',
       ARRAY['tickets:read', 'invoices:read', 'quotes:read', 'contracts:read',
             'assets:read', 'projects:read', 'kb:read', 'notifications:read'],
       TRUE
FROM tenants t
ON CONFLICT (tenant_id, name) DO NOTHING;
