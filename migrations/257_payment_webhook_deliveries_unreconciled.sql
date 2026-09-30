-- PMS-1432: `outcome` gains a fifth value, `unreconciled`, for a delivery that
-- verified and dispatched but whose reconciliation `record_gateway_payment`
-- itself refused (the `Draft|Pending` guard, PMS-999/PMS-1444, or the invoice
-- having been deleted between checkout and webhook). Before this, the
-- `PaymentSucceeded` arm left `outcome` at its `"accepted"` default regardless
-- of whether a `payments` row was actually written, so a refused
-- reconciliation was indistinguishable in this table from a real success.
--
-- `accepted`, `refused`, `ignored` and `failed` are migration 213's, immutable,
-- and stay exactly as they were; this only widens the CHECK.
ALTER TABLE payment_webhook_deliveries DROP CONSTRAINT payment_webhook_deliveries_outcome_check;
ALTER TABLE payment_webhook_deliveries ADD CONSTRAINT payment_webhook_deliveries_outcome_check CHECK (
    outcome IN ('accepted', 'refused', 'ignored', 'failed', 'unreconciled')
);
