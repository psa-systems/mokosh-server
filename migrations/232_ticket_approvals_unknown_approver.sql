-- PMS-1230: let a sole approver/requester contact be deleted.
--
-- Migration 143 promised (its own header, lines 18-20) that deleting a
-- contact who is an approval's sole approver would leave the row intact,
-- "surfacing as 'unknown approver' in the UI". The `ON DELETE SET NULL`
-- on `approver_contact_id` does exactly that to the column, but the
-- `ticket_approvals_approver_xor` CHECK still demands exactly one of the
-- three approver columns be set, so the resulting all-NULL row violates
-- it (23514) and the DELETE that triggered the SET NULL is rolled back
-- with it. A contact who is a sole approver can therefore never be
-- deleted while that approval exists.
--
-- Migration 181 has the same defect on the requester side, one degree
-- worse: `requested_by_contact_id` has no `ON DELETE` action at all, so
-- deleting the contact fails with a bare FK violation (23503) before the
-- CHECK is ever evaluated.
--
-- Fix, both sides: widen the XOR to also permit the all-NULL state (0 of
-- N columns set), meaning "unknown" rather than "misconfigured", and give
-- `requested_by_contact_id` the same `ON DELETE SET NULL` the approver
-- column already has so the FK does not block the delete before the
-- (now-widened) CHECK gets a say. Existing rows all have exactly one
-- column set on each axis, so relaxing `= 1` to `<= 1` is safe against
-- live data.

ALTER TABLE ticket_approvals
    DROP CONSTRAINT ticket_approvals_approver_xor;

ALTER TABLE ticket_approvals
    ADD CONSTRAINT ticket_approvals_approver_xor
        CHECK (
            (CASE WHEN approver_user_id    IS NOT NULL THEN 1 ELSE 0 END)
          + (CASE WHEN approver_role       IS NOT NULL THEN 1 ELSE 0 END)
          + (CASE WHEN approver_contact_id IS NOT NULL THEN 1 ELSE 0 END)
          <= 1
        );

ALTER TABLE ticket_approvals
    DROP CONSTRAINT ticket_approvals_requester_xor;

ALTER TABLE ticket_approvals
    DROP CONSTRAINT ticket_approvals_requested_by_contact_id_fkey;

ALTER TABLE ticket_approvals
    ADD CONSTRAINT ticket_approvals_requested_by_contact_id_fkey
        FOREIGN KEY (requested_by_contact_id) REFERENCES contacts(id) ON DELETE SET NULL;

ALTER TABLE ticket_approvals
    ADD CONSTRAINT ticket_approvals_requester_xor
        CHECK (
            (CASE WHEN requested_by_id         IS NOT NULL THEN 1 ELSE 0 END)
          + (CASE WHEN requested_by_contact_id IS NOT NULL THEN 1 ELSE 0 END)
          <= 1
        );

COMMENT ON CONSTRAINT ticket_approvals_approver_xor ON ticket_approvals IS
    'PMS-1230: at most one approver column set. All-NULL means the sole approver contact was deleted; surfaced as "unknown approver".';

COMMENT ON CONSTRAINT ticket_approvals_requester_xor ON ticket_approvals IS
    'PMS-1230: at most one requester column set. All-NULL means the sole requester contact was deleted; surfaced as "unknown requester".';
