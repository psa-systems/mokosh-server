-- PMS-929 (mokosh-contact-login prompt 012): let a portal role be scoped
-- to a single Company inside a tenant, alongside the existing tenant-wide
-- roles seeded by migration 142.
--
-- A NULL `company_id` marks the row as tenant-wide (the three built-ins
-- Billing Contact / Support Contact / Read-Only stay here). A non-NULL
-- `company_id` marks the row as Company-scoped: only assignable to
-- contacts of THAT Company, invisible to every other Company under the
-- same tenant. Deleting the parent Company cascades the scoped roles
-- with it (assignments cascade through `contact_role_assignments`).
--
-- Uniqueness moves from a plain `UNIQUE (tenant_id, name)` (which
-- forbade the "Billing" name across scopes) to a pair of partial UNIQUE
-- indexes on `LOWER(name)` so the two semantics compose:
--   * portal_roles_tenant_wide_name_uniq
--       WHERE company_id IS NULL
--       -> tenant-wide names unique within a tenant
--   * portal_roles_company_scoped_name_uniq
--       WHERE company_id IS NOT NULL
--       -> Company-scoped names unique within (tenant, company)
--
-- Same name across scopes is intentionally allowed: a tenant-wide "Billing"
-- and a Company-X-scoped "Billing" coexist, and two different Companies
-- can each define their own "Billing". Case-insensitive to match the
-- existing `PortalRoleService::create_role` uniqueness probe.
--
-- The plain UNIQUE from migration 139 must go away in the same migration
-- so it does not fight the tenant-wide partial index (both would fire on
-- a same-cased tenant-wide duplicate, but the partial index carries the
-- correct scope semantics; the plain constraint would forbid the
-- cross-scope duplicate we now allow).

ALTER TABLE portal_roles
    ADD COLUMN company_id UUID REFERENCES companies(id) ON DELETE CASCADE;

ALTER TABLE portal_roles
    DROP CONSTRAINT portal_roles_tenant_id_name_key;

CREATE UNIQUE INDEX portal_roles_tenant_wide_name_uniq
    ON portal_roles (tenant_id, LOWER(name))
    WHERE company_id IS NULL;

CREATE UNIQUE INDEX portal_roles_company_scoped_name_uniq
    ON portal_roles (tenant_id, company_id, LOWER(name))
    WHERE company_id IS NOT NULL;

CREATE INDEX idx_portal_roles_company_scope
    ON portal_roles (tenant_id, company_id)
    WHERE company_id IS NOT NULL;
