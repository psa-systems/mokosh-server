-- PMS-1035: prepaid block hours are not invoiced again, and overage bills
-- at the overage rate.
--
-- PMS-951 made a prepaid block draw down when time is logged
-- (`time_entries.hours_consumed`, `hours_balance_id`) and left the billing
-- half undone: PMS-944 arms every billable client entry `ready_to_bill` at
-- creation and `create_invoice_from_time_entries` bills every such entry at
-- `hourly_rate * hours`, so an entry drawn from a block the customer already
-- paid for was invoiced a second time, and its overage was priced at the
-- hourly rate rather than the contract's `overage_rate`.
--
-- `prepaid` is a fourth `billing_status`: the entry was fully covered by a
-- block-hours allotment and there is nothing to charge for it. It is NOT
-- `billed`, which means "on an invoice", and the invoice builder selects
-- `ready_to_bill` only, so a `prepaid` entry never reaches one. Releasing
-- the draw (an edit, a delete, a date move) puts the entry back to
-- `ready_to_bill`.
--
-- An entry that ran past the block keeps `ready_to_bill` and records the
-- overage beside the draw: `overage_hours` (the part past the allotment)
-- and `overage_rate` (the contract item's rate at the moment of the draw,
-- NULL when the item names none, in which case the entry's own hourly rate
-- applies). The invoice builder bills such an entry for `overage_hours` at
-- that rate and nothing for the prepaid part.
ALTER TABLE time_entries DROP CONSTRAINT time_entries_billing_status_check;
ALTER TABLE time_entries
    ADD CONSTRAINT time_entries_billing_status_check
    CHECK (billing_status IN ('not_billed', 'ready_to_bill', 'billed', 'prepaid'));

ALTER TABLE time_entries
    ADD COLUMN overage_hours DECIMAL(10, 2),
    ADD COLUMN overage_rate DECIMAL(10, 2);
