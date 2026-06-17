-- PMS-373: a payment amount must be strictly positive. The create/update path
-- now rejects amount <= 0 with a 422, but a DB CHECK constraint backstops the
-- rule for any other writer (bulk imports, future endpoints, manual SQL).
--
-- The constraint is added NOT VALID so this migration does not fail on rows
-- that pre-date the rule (the bug allowed negative/zero amounts to be stored).
-- NOT VALID still enforces `amount > 0` on every new INSERT and on any UPDATE
-- of an existing row; it only skips the one-time scan of historical rows.
--
-- Existing offending rows are surfaced (not silently mutated) so finance can
-- reconcile them deliberately. Inspect and clean up with:
--   SELECT id, tenant_id, company_id, payment_date, amount
--   FROM payments WHERE amount <= 0 ORDER BY payment_date;
-- After cleanup the constraint can be validated tenant-wide with:
--   ALTER TABLE payments VALIDATE CONSTRAINT payments_amount_positive;

DO $$
DECLARE
    bad_count BIGINT;
BEGIN
    SELECT count(*) INTO bad_count FROM payments WHERE amount <= 0;
    IF bad_count > 0 THEN
        RAISE WARNING 'PMS-373: % existing payment row(s) have amount <= 0 and require manual cleanup; see SELECT ... FROM payments WHERE amount <= 0', bad_count;
    END IF;
END $$;

ALTER TABLE payments
    ADD CONSTRAINT payments_amount_positive CHECK (amount > 0) NOT VALID;
