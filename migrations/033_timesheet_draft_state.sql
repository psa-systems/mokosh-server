-- PMS-183: add a 'draft' (unsubmitted) approval state for time entries so a
-- submitted timesheet can be withdrawn back to draft, and a freshly logged
-- entry starts unsubmitted instead of immediately awaiting approval.
--
-- Before this, approval_status only allowed ('pending', 'approved',
-- 'rejected') and DEFAULTed to 'pending', so every new time entry looked
-- "submitted for approval" the moment it was created and there was no state
-- to withdraw back to. We widen the CHECK to include 'draft' and make it the
-- default; 'submit' moves draft/rejected -> pending and 'withdraw' moves
-- pending -> draft (the new endpoint), giving a real draft -> submit -> approve
-- lifecycle.
--
-- Existing rows are left untouched: any row already at 'pending'/'approved'/
-- 'rejected' keeps its state, so no in-flight approval is disturbed. Only
-- rows created after this migration default to 'draft'.

ALTER TABLE time_entries DROP CONSTRAINT time_entries_approval_status_check;

ALTER TABLE time_entries
    ADD CONSTRAINT time_entries_approval_status_check
    CHECK (approval_status IN ('draft', 'pending', 'approved', 'rejected'));

ALTER TABLE time_entries ALTER COLUMN approval_status SET DEFAULT 'draft';
