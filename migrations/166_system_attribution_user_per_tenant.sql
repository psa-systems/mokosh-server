-- MAPPS-562: system attribution user per tenant
--
-- TicketService::create_portal_ticket (src/modules/tickets/service.rs
-- around line 2028), TicketService::accept_portal_note (line 2260),
-- and the whole email_intake service all need a `users` row to write
-- into tickets.created_by_id (NOT NULL FK to users). The fallback query
-- reads:
--
--   SELECT id FROM users
--   WHERE tenant_id = $1 AND status = 'active'
--     AND role IN ('super_admin', 'admin', 'manager')
--   ORDER BY created_at LIMIT 1
--
-- Post-MAPPS-554 the tenant provisioning path stopped inserting any users
-- row (mokosh-apps now live entirely on the contacts plane), so fresh
-- tenants had zero admin/manager users. Portal ticket creation therefore
-- 500'd with CONFIGURATION_ERROR ("tenant has no admin/manager user to
-- attribute it to"), blocking the one write path a client should have.
-- This migration backfills a hidden "system" users row for every tenant
-- that has no eligible fallback user, and the paired code change in
-- TenantService::create_tenant inserts the same row for new tenants.
--
-- Row shape:
--   email = 'system+<slug>@mokosh.local'  reserved suffix; will not
--                                          collide with real users or
--                                          the mokosh operator; easy to
--                                          filter from admin lists in a
--                                          follow-up.
--   role = 'admin'                         matches the fallback query.
--   status = 'active'                      matches the fallback filter.
--   password_hash = NULL                   AuthService::login early-outs
--                                          with 401 on NULL hash, so the
--                                          row is unloginable.
--   first_name = 'System', last_name = 'Attribution'  distinctive labels
--                                          for the audit trail.
--
-- The MAPPS-498 users -> identities mirror trigger will fire on each
-- INSERT here and create matching identity + tenant_membership rows;
-- since password_hash is NULL, no authentication path works against
-- them.
--
-- Idempotent: the WHERE clause skips tenants that already carry an
-- eligible user (all pre-554 tenants), and the ON CONFLICT clause
-- skips a re-run.
INSERT INTO users (tenant_id, email, first_name, last_name, role, status)
SELECT t.id,
       'system+' || t.slug || '@mokosh.local',
       'System',
       'Attribution',
       'admin',
       'active'
FROM tenants t
WHERE NOT EXISTS (
    SELECT 1 FROM users u
    WHERE u.tenant_id = t.id
      AND u.status = 'active'
      AND u.role IN ('super_admin', 'admin', 'manager')
)
ON CONFLICT (tenant_id, email) DO NOTHING;
