-- PMS-1036: write off an invoice that will not be paid, distinct from
-- crediting it.
--
-- `written_off` has been a value of `invoices.status` since migration 010
-- and a member of `InvoiceStatus::is_frozen` since PMS-580, and nothing ever
-- wrote it (migration 122 records the same for `void`, which PMS-953 then
-- gave a writer). A credit note is the wrong tool for the case: it says the
-- customer does not owe this and reduces revenue. A write-off says the
-- customer owes it and will not pay, a bad-debt expense; the books treat the
-- two differently and a statement shows one and not the other.
--
-- The four columns are the record of the decision: when, by whom, why, and
-- the balance at that moment. `write_off_amount` is frozen because
-- `balance_due` keeps moving if a late payment lands afterwards; the debt
-- was not forgiven, so `balance_due` itself is left alone.
ALTER TABLE invoices
    ADD COLUMN written_off_at TIMESTAMPTZ,
    ADD COLUMN written_off_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN write_off_reason TEXT,
    ADD COLUMN write_off_amount DECIMAL(12, 2);

CREATE INDEX idx_invoices_written_off
    ON invoices (tenant_id, company_id, written_off_at)
    WHERE written_off_at IS NOT NULL;
