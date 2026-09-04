-- PMS-1029: tax is computed from the tenant's rate, and the invoice records it.
--
-- `tax_rates` has carried a per-tenant default since migration 010, seeded as
-- `No Tax` at 0 by 023, kept to one default by 049, with full CRUD. Nothing
-- applied it: every writer took `tax_amount` as a number the caller supplied,
-- or wrote zero. And the rate is a PERCENT everywhere it is handled (the
-- validator accepts 0 to 100, the SPA divides by 100) while DECIMAL(5,4)
-- holds at most 9.9999, so a 10% or 13% rate could not even be stored.

-- A percent with four decimals, up to 999.9999. Widening only; every stored
-- value fits.
ALTER TABLE tax_rates ALTER COLUMN rate TYPE DECIMAL(7, 4);

-- A line is taxable or not. A product line copies `products.is_taxable` at
-- write time, the way it copies `unit_price` (PMS-955): stored per line and
-- never read through to the product, so a catalog edit cannot re-tax an
-- issued document. Every line that exists today was taxed by a figure typed
-- in beside it, so TRUE is the honest backfill: the flag changes nothing
-- until a rate is applied to a new invoice.
ALTER TABLE invoice_lines
    ADD COLUMN is_taxable BOOLEAN NOT NULL DEFAULT TRUE;

-- The rate an invoice was taxed at, FROZEN on the invoice so the document can
-- print it and a later edit to `tax_rates` does not re-price an issued
-- document (the shape `payment_term_id` plus a recorded count has since
-- PMS-990). NULL on every existing row and on a row whose `tax_amount` was
-- supplied rather than derived: "amount as given", which is what they were.
ALTER TABLE invoices
    ADD COLUMN tax_rate_id UUID REFERENCES tax_rates(id),
    ADD COLUMN tax_rate DECIMAL(7, 4);
