-- MAPPS-554: contacts.portal_role
--
-- Persists whether a portal-enabled contact is the tenant's portal
-- OWNER (provisioned by TenantService::create_tenant post-554) or a
-- SUB-USER added via the existing PMS-729 invite_colleague endpoint.
-- Pre-554 contacts stay at NULL: agent-flipped is_portal_user rows
-- from before this migration have no owner/user distinction yet, and
-- the portal itself does not gate any behavior on the column today
-- (the follow-up is: only portal_role='admin' contacts see the
-- sub-user invite tab).
--
-- Only 'admin' and 'user' are legal. Left nullable so pre-existing
-- rows do not need a backfill; new rows written by post-554 code paths
-- MUST set an explicit value or the CHECK constraint stays green
-- vacuously.
ALTER TABLE contacts
    ADD COLUMN portal_role VARCHAR(20)
    CHECK (portal_role IS NULL OR portal_role IN ('admin', 'user'));

-- Support the "who is the tenant's portal owner?" lookup that
-- resend_admin_welcome and (future) portal sub-user management need.
-- Partial index on portal-enabled rows only: the vast majority of
-- contacts have is_portal_user = false and would just bloat the
-- index. Ordering by (tenant_id, portal_role) matches the shape of
-- `SELECT ... WHERE tenant_id = $1 AND portal_role = 'admin' AND
-- is_portal_user = true`.
CREATE INDEX idx_contacts_portal_role_active
    ON contacts (tenant_id, portal_role)
    WHERE is_portal_user = true;
