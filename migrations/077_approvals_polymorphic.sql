-- PMS-470 / PMS-451 phase 2: polymorphic approvals.
--
-- PMS-451 phase 1 shipped per-ticket approval requests; the surface
-- proved out and the second consumer (time entries above a billable
-- threshold) is now real. This migration widens the table so the same
-- request / decide / cancel surface drives sign-off across every
-- entity type without duplicating tables, queries, or indexes.
--
-- Two new columns + a CHECK on `target`:
--
--   target VARCHAR(20)   - the parent entity kind. 'ticket' covers
--                          the phase-1 rows; 'change_request',
--                          'quote', 'time_entry' are the phase-2
--                          additions. Free-text inside the CHECK so
--                          a future surface (e.g. 'expense') can be
--                          added with a CHECK widen rather than a
--                          full schema migration.
--   entity_id UUID       - the parent entity's PK in its own table.
--                          For target='ticket' this equals the
--                          legacy `ticket_id` column; for other
--                          targets the column has no FK to keep the
--                          table polymorphic (the tenant-scoped
--                          existence check is enforced at the route
--                          layer where the parent table is known).
--
-- The legacy `ticket_id` column is preserved (made nullable) for
-- backwards-compatible reads from existing consumers; a non-ticket
-- row carries NULL there. New code should read `(target, entity_id)`;
-- the old column will be dropped in a future migration once every
-- consumer has migrated.
--
-- The existing indexes on `(tenant_id, ticket_id)` and the partial
-- pending indexes stay (they still serve ticket-only queries on the
-- legacy column). New indexes target the polymorphic columns so the
-- cross-entity scans the generic surface needs land as one-index
-- lookups.

ALTER TABLE ticket_approvals
    ADD COLUMN target VARCHAR(20) NOT NULL DEFAULT 'ticket'
        CHECK (target IN ('ticket', 'change_request', 'quote', 'time_entry')),
    ADD COLUMN entity_id UUID;

-- Backfill: every existing row was a ticket approval, so its
-- entity_id is its ticket_id and target stays at the default.
UPDATE ticket_approvals
   SET entity_id = ticket_id
 WHERE entity_id IS NULL;

-- entity_id is mandatory going forward. Apply NOT NULL after the
-- backfill so the migration is safe to re-run from a half-applied
-- state.
ALTER TABLE ticket_approvals
    ALTER COLUMN entity_id SET NOT NULL;

-- Relax ticket_id to nullable so non-ticket targets can leave it
-- empty without violating the legacy NOT NULL constraint.
ALTER TABLE ticket_approvals
    ALTER COLUMN ticket_id DROP NOT NULL;

-- Tenant + target + entity scan: "show me every approval on entity
-- (target, id)". Lets the per-entity routes (`GET
-- /api/v1/{target_plural}/{id}/approvals`) land as one index scan
-- regardless of which target the SPA is reading.
CREATE INDEX idx_ticket_approvals_target_entity
    ON ticket_approvals(tenant_id, target, entity_id);

-- Pending-queue scans: same shape as the phase-1 indexes but on
-- (target, entity_id) so the polymorphic "pending for user U"
-- surface can filter by target too if the SPA wants per-tab counts.
CREATE INDEX idx_ticket_approvals_target_user_pending
    ON ticket_approvals(tenant_id, target, approver_user_id)
    WHERE status = 'pending' AND approver_user_id IS NOT NULL;

CREATE INDEX idx_ticket_approvals_target_role_pending
    ON ticket_approvals(tenant_id, target, approver_role)
    WHERE status = 'pending' AND approver_role IS NOT NULL;
