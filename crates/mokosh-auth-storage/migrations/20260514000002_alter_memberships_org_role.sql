-- Add a 3-state `org_role` column to memberships so the /v1/orgs/*
-- surface can model "owner / admin / member" without collapsing it
-- onto the 5-state global UserRole. The existing `role` column stays
-- as the per-tenant mirror of the global role (Admin/Manager/...);
-- this new column drives the org-membership UI exclusively.
--
-- See docs/mokosh-fixes/03-organizations.md (Open question #4).

ALTER TABLE mokosh_auth.memberships
    ADD COLUMN org_role TEXT
        CHECK (org_role IN ('owner', 'admin', 'member'));

-- Backfill: collapse the global role onto the 3-state. Existing
-- members in org tenants become 'admin' (they're early adopters /
-- seed data; granular roles can be assigned via the new endpoints).
-- Members of personal tenants get 'owner' (they are the sole owner of
-- their personal namespace).
UPDATE mokosh_auth.memberships m
SET org_role = CASE
    WHEN EXISTS (SELECT 1 FROM public.tenants t
                 WHERE t.id = m.tenant_id AND t.kind = 'personal')
        THEN 'owner'
    WHEN m.role = 'admin' THEN 'admin'
    ELSE 'member'
END
WHERE org_role IS NULL;

ALTER TABLE mokosh_auth.memberships
    ALTER COLUMN org_role SET NOT NULL;
