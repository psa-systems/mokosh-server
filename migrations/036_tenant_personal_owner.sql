-- PMS-244 phase 2: orgs live in Mokosh, so the `bunyip_org_id` claim approach
-- (PMS-240, migration 034) is dropped. Repurpose the column as
-- `personal_owner_id`: the user who owns a one-person `personal` tenant, used to
-- find-or-provision a personal tenant on self-signup. The old column carried no
-- real data (the Bunyip claim never shipped), so this is a clean drop + add.

DROP INDEX IF EXISTS idx_tenants_bunyip_org_id;
ALTER TABLE tenants DROP COLUMN IF EXISTS bunyip_org_id;

-- No FK to users(id) on purpose: the personal tenant is provisioned on the
-- owner's first login BEFORE their user row is JIT-mirrored into it (the user
-- needs the tenant to exist first), so a FK would be a chicken-and-egg cycle.
-- It is a soft owner pointer; the matching user row lands moments later.
ALTER TABLE tenants ADD COLUMN personal_owner_id UUID;

CREATE UNIQUE INDEX idx_tenants_personal_owner_id
    ON tenants (personal_owner_id)
    WHERE personal_owner_id IS NOT NULL;
