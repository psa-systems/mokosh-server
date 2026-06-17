-- PMS-400: reject duplicate company names within a tenant.
--
-- ContactService::create_company / update_company
-- (src/modules/contacts/service.rs) check name existence at the
-- application layer before INSERT/UPDATE and return 409 Conflict on a
-- duplicate within the tenant (case-insensitive, trimmed). This index is
-- the database backstop for the same invariant so a concurrent insert
-- that races the app-layer SELECT still fails closed: the resulting
-- SQLSTATE 23505 is mapped to AppError::Conflict by the service.
--
-- Match on lower(btrim(name)) so "Acme", "acme", and " Acme " collide,
-- matching the trim the SPA applies and the server-side
-- validate_company_name whitespace rule. The non-unique idx_companies_name
-- (migration 004) stays for substring/prefix lookups.
--
-- Assumes no tenant currently holds duplicate company names; if this index
-- build fails on existing data, dedupe the offending rows in a one-off
-- step first and re-run.

CREATE UNIQUE INDEX idx_companies_tenant_name_unique
    ON companies (tenant_id, lower(btrim(name)));
