-- PMS-951: record what a time entry drew from a block-hours contract.
--
-- `time_entries.contract_id` has existed since `006_time_tracking.sql` and
-- `consume_approved_hours` has read it since PMS-405, and nothing ever set it:
-- neither INSERT lists the column, it is on neither request DTO, and the only
-- writer in the tree is direct SQL in `tests/contracts.rs`. So a block-hours
-- contract was never drawn against by time logged in the app. The balance sat
-- at its opening `hours_included` for the period, `hours_remaining` never fell,
-- and no overage was ever computed, which means an MSP selling a prepaid block
-- was billing hourly for work the client had already paid for.
--
-- Setting `contract_id` is most of the fix. These two columns are the rest,
-- and they exist because consumption has to survive an edit.
--
-- `hours_consumed` is the APPLIED hours, not the entry's duration: consuming
-- ten hours against an eight-hour allotment applies eight and leaves two as
-- overage, and only the applied part came out of the balance. Recording what
-- was actually taken is what makes a release exact and order-independent, where
-- recomputing it from the duration later would have to re-derive a split that
-- depended on the balance at the time.
--
-- `hours_balance_id` names the row it came out of, rather than re-deriving the
-- period on the way back. An edit can move an entry's date into another
-- billing period, and a release that recomputed the period would then credit
-- hours to a period that never paid for them.
--
-- Together they are also the idempotency guard. `hours_consumed IS NOT NULL`
-- means this entry has already drawn, and every claim is
-- `WHERE ... hours_consumed IS NULL`, the same shape PMS-956 uses for a
-- one-time contract item. Before this the only guard anywhere was
-- `approve_timesheet`'s `WHERE approval_status = 'pending'`, which is not a
-- guard on consumption at all: it is a guard on approval that consumption
-- happened to hang off.
ALTER TABLE time_entries ADD COLUMN hours_consumed DECIMAL(10, 2);

-- SET NULL rather than CASCADE: deleting a contract takes its balance rows with
-- it, and a time entry must survive that. The entry then has nothing to release
-- to, which is correct - the allotment it drew from no longer exists.
ALTER TABLE time_entries
    ADD COLUMN hours_balance_id UUID REFERENCES contract_hour_balances(id) ON DELETE SET NULL;

-- The claim predicate, so finding what a contract has drawn does not scan.
CREATE INDEX idx_time_entries_consumed
    ON time_entries (tenant_id, contract_id)
    WHERE hours_consumed IS NOT NULL;

-- No backfill, deliberately. Every existing entry has a NULL `contract_id`, so
-- there is nothing to attribute: the hours were never drawn and the app has no
-- record of which contract they would have come from. Inventing that from the
-- company today would draw months of historical time against a CURRENT period's
-- allotment and hand an MSP an overage bill for work already invoiced hourly.
-- Consumption starts from here.
