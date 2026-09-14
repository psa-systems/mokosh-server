-- MAPPS-673: minimum acceptable amount for a partial-payment mint, per
-- gateway config. NULL means "use the code default" (currently $1.00 via
-- `BillingService::default_min_partial_amount`), which is what every row
-- gets when this column ships; a tenant that wants a higher floor to
-- offset gateway fees sets a value here through the admin API.
--
-- The floor exists because Stripe / PayPal charge a fixed cent + a
-- percentage per authorised transaction. A payment for $0.10 costs about
-- 32c on Stripe (30c + 2.9%), so an unchecked partial-payment endpoint
-- lets a bad actor drain a tenant's gateway budget one dime at a time.
-- The MAPPS-673 endpoint refuses any amount below this floor.
--
-- NUMERIC(10,2) mirrors `invoices.balance_due` and every other money column
-- in this table's sibling tables.

ALTER TABLE payment_gateway_configs
    ADD COLUMN min_partial_amount NUMERIC(10, 2) NULL;
