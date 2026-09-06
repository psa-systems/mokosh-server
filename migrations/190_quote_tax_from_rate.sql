-- PMS-1038: a quote's tax is derived from the tenant's rate, the PMS-1029
-- shape on quotes.
--
-- `quotes.tax_amount` was a number the caller supplied, and the customer
-- signs the quote's total, so a wrong figure here is one the customer
-- accepted. The rate is FROZEN on the quote for the same reason it is on an
-- invoice: a later edit to `tax_rates` must not move a total a customer has
-- seen. NULL on every existing row and on a quote whose amount was supplied:
-- "amount as given", which is what they were, and which `recompute_totals`
-- leaves alone.
ALTER TABLE quote_lines
    ADD COLUMN is_taxable BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE quotes
    ADD COLUMN tax_rate_id UUID REFERENCES tax_rates(id),
    ADD COLUMN tax_rate DECIMAL(7, 4);
