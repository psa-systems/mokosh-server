-- PMS-240: map a Bunyip org to a mokosh tenant.
--
-- Bunyip-issued access tokens will carry an opaque org identifier. This server
-- resolves it to a mokosh tenant via this column, auto-provisioning a tenant on
-- first login of a new org (see TenantService::ensure_tenant_for_bunyip_org).
-- Nullable: legacy / standalone tenants have no Bunyip org. The partial unique
-- index lets many tenants stay NULL while guaranteeing one tenant per org.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS bunyip_org_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_bunyip_org_id
    ON tenants (bunyip_org_id)
    WHERE bunyip_org_id IS NOT NULL;
