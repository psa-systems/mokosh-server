-- Widen the `bill_payments.payment_method` CHECK to include 'paypal'.
--
-- Migration 287 copied the `payments` CHECK vocabulary when it added
-- `bill_payments`, and its comment claims the two sets stay in step. They did
-- not: migration 233 had already widened `payments.payment_method` to accept
-- 'paypal', four migrations earlier, and 287 missed it. A bill paid through a
-- PayPal connection currently fails the receivables-side CHECK, with no code
-- path that distinguishes receivables from payables.
--
-- Migrations are immutable, so widening the CHECK is a new migration rather
-- than an edit to 287.

ALTER TABLE bill_payments
    DROP CONSTRAINT bill_payments_payment_method_check,
    ADD CONSTRAINT bill_payments_payment_method_check
        CHECK (payment_method IN ('check', 'credit_card', 'ach', 'wire', 'cash', 'paypal', 'other'));
