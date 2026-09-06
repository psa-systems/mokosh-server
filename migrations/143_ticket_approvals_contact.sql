-- PMS-729 phase 2 §7 slice D / I7: portal contact approvers.
--
-- Approvals arrive on the `ticket_approvals` table (misnamed since
-- PMS-470 widened it to change_request / quote / time_entry via the
-- polymorphic `target` column; keeping the name so existing consumers
-- do not have to rename). Phase 1 assigned an approver by user id or
-- by role; a portal customer is neither. This migration adds a third
-- optional column so an agent can route a decision at a specific
-- portal contact, and the portal caller can list their own pending
-- decisions without every route re-inventing the join.
--
-- The old XOR constraint on `(approver_user_id, approver_role)` is
-- widened to XOR-of-three: exactly one of the three approver columns
-- must be set. Existing rows all have exactly one populated, so the
-- rewrite is safe against live data; the CHECK is re-created against
-- the new predicate to enforce it for all new rows.
--
-- The FK to contacts is `ON DELETE SET NULL` so a deleted contact
-- leaves the approval intact (surfacing as "unknown approver" in the
-- UI) rather than cascading the historical record away.
--
-- Partial index on `(tenant_id, approver_contact_id) WHERE status =
-- 'pending' AND approver_contact_id IS NOT NULL` matches the two
-- existing partial indexes for user + role approvers; the portal
-- inbox counter reads through it.

ALTER TABLE ticket_approvals
    ADD COLUMN approver_contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL;

ALTER TABLE ticket_approvals
    DROP CONSTRAINT ticket_approvals_approver_xor;

ALTER TABLE ticket_approvals
    ADD CONSTRAINT ticket_approvals_approver_xor
        CHECK (
            (CASE WHEN approver_user_id    IS NOT NULL THEN 1 ELSE 0 END)
          + (CASE WHEN approver_role       IS NOT NULL THEN 1 ELSE 0 END)
          + (CASE WHEN approver_contact_id IS NOT NULL THEN 1 ELSE 0 END)
          = 1
        );

CREATE INDEX idx_ticket_approvals_contact_pending
    ON ticket_approvals(tenant_id, approver_contact_id)
    WHERE status = 'pending' AND approver_contact_id IS NOT NULL;

COMMENT ON COLUMN ticket_approvals.approver_contact_id IS
    'PMS-729 phase 2 §7 slice D / I7: portal contact assigned as the decision-maker on this approval. Mutually exclusive with approver_user_id and approver_role.';
