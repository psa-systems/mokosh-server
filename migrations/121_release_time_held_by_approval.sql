-- PMS-944: release the client time that the old approval gate is holding.
--
-- PMS-144 made weekly timesheet approval the billing gate: `approve_timesheet`
-- was the only statement that ever wrote `billing_status = 'ready_to_bill'` on
-- a time entry, and the invoice builder bills only that status. Every billable
-- client hour logged but never countersigned is therefore sitting at the
-- `not_billed` DEFAULT and cannot reach an invoice. From this migration on the
-- service arms an entry at creation, which fixes new rows and leaves every
-- existing one stranded, so they are armed here.
--
-- Scope, clause by clause:
--
--   entry_kind = 'client'  PMS-942: employee time bills nobody. Arming it would
--                          make the MSP's own overhead invoiceable, which is
--                          the exact defect PMS-942 closed.
--   is_billable = TRUE     Non-billable time was a decision somebody made when
--                          they logged it. This migration releases a gate; it
--                          does not overturn that decision.
--   invoice_id IS NULL     A row already on an invoice keeps `billed`. Re-arming
--                          it would put the same work on a second invoice.
--   billing_status <>      Belt and braces with the clause above, and the thing
--     'billed'             that makes this migration safe to reason about on its
--                          own: nothing already billed is touched.
--
-- `approval_status` is deliberately NOT changed. Forcing draft and pending rows
-- to 'approved' would fabricate an approval with a null `approved_by_id`, and on
-- a tenant that has timesheets on (PMS-943) it would sign off weeks that nobody
-- has looked at, destroying real in-flight review. The acceptance criterion is
-- that no hours are lost behind a gate that no longer exists, and releasing
-- `billing_status` is what satisfies it. Approval keeps its own lifecycle for
-- the timesheet and simply stops being a billing fact.

UPDATE time_entries
SET billing_status = 'ready_to_bill',
    updated_at     = NOW()
WHERE entry_kind     = 'client'
  AND is_billable    = TRUE
  AND invoice_id IS NULL
  AND billing_status <> 'billed'
  AND billing_status <> 'ready_to_bill';
