-- Widen the `payments.payment_method` CHECK to include 'paypal'.
--
-- PMS-1235: `record_gateway_payment` hardcoded 'credit_card' for every
-- gateway-confirmed payment, so a PayPal checkout recorded a Stripe-shaped
-- method. The column's CHECK never allowed anything else, so the fix in
-- `BillingService::record_gateway_payment` needs a value the constraint
-- accepts before it can record the provider that actually took the payment.
--
-- Migrations are immutable, so widening the CHECK is a new migration rather
-- than an edit of 010.

ALTER TABLE payments
    DROP CONSTRAINT payments_payment_method_check,
    ADD CONSTRAINT payments_payment_method_check
        CHECK (payment_method IN ('check', 'credit_card', 'ach', 'wire', 'cash', 'paypal', 'other'));
