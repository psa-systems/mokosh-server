-- PMS-711: schema for the tenant-owned payment-provider integration (Stripe
-- Pay Now first; the provider interface is adapter-shaped so PayPal follows
-- without a schema change).
--
-- Three changes, all additive:
--
-- 1. `payments.currency` - the paid-amount currency the provider reports on the
--    webhook. `payments` previously carried only `amount`; the invoice's own
--    `currency` was the implicit unit. The acceptance criteria call for the
--    synced payment to record currency explicitly, so store it per payment.
--    Nullable: existing manual payment rows keep NULL (they inherit the
--    invoice currency exactly as before), only gateway-synced rows set it.
--
-- 2. `payments_tenant_gateway_txn_uq` - webhook idempotency. Stripe redelivers
--    an event until it gets a 2xx, so the same `payment_intent` can arrive more
--    than once. A partial UNIQUE on `(tenant_id, gateway_transaction_id)` (only
--    where the id is present) lets the paid-sync INSERT use `ON CONFLICT DO
--    NOTHING`: the first delivery records the payment, every redelivery no-ops.
--    Partial so the pre-existing manual payments (all NULL gateway id) are
--    unaffected and multiple manual rows stay legal.
--
-- 3. `payment_refunds` - refunds against a synced payment. `payments.amount`
--    is CHECK (amount > 0) (migration 052), so a refund cannot be a negative
--    payment row; it is a first-class row here instead. `recompute_invoice_
--    payment_state` (billing/service.rs) subtracts SUM(payment_refunds.amount)
--    from SUM(payments.amount) to get `invoices.amount_paid`, so a full refund
--    returns the invoice to a `sent` (unpaid) balance and a partial refund to
--    `partially_paid`. `provider_reference` is the Stripe refund id (`re_...`);
--    UNIQUE (tenant_id, provider_reference) makes refund replay idempotent the
--    same way the payments index does.

ALTER TABLE payments ADD COLUMN currency VARCHAR(3);

CREATE UNIQUE INDEX payments_tenant_gateway_txn_uq
    ON payments (tenant_id, gateway_transaction_id)
    WHERE gateway_transaction_id IS NOT NULL;

CREATE TABLE payment_refunds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The payment this refund reverses. CASCADE so deleting a payment (only
    -- legal for unposted rows) takes its refund history with it.
    payment_id UUID NOT NULL REFERENCES payments(id) ON DELETE CASCADE,
    -- Denormalised from the payment so the invoice recompute can SUM refunds
    -- by invoice without a join. SET NULL mirrors an unapplied payment.
    invoice_id UUID REFERENCES invoices(id) ON DELETE SET NULL,
    amount DECIMAL(12, 2) NOT NULL CHECK (amount > 0),
    currency VARCHAR(3),
    provider VARCHAR(30) NOT NULL DEFAULT 'stripe',
    -- Provider's own refund id (Stripe `re_...`). The idempotency key.
    provider_reference VARCHAR(255) NOT NULL,
    gateway_response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider_reference)
);

CREATE INDEX idx_payment_refunds_invoice ON payment_refunds (tenant_id, invoice_id);
CREATE INDEX idx_payment_refunds_payment ON payment_refunds (tenant_id, payment_id);

-- Fail-closed tenant isolation. Policy shape mirrors 038_rls_fail_closed.sql /
-- 094 / 095 exactly: an unset or empty `app.current_tenant` collapses to NULL,
-- so USING matches no rows (fail-closed read) and WITH CHECK rejects the write;
-- FORCE binds the table owner too. Every serving access to this table goes
-- through `Database::begin_with_tenant`; the Stripe webhook's cross-tenant
-- pre-auth reads run on the BYPASSRLS migrator pool with a SAFETY note.
ALTER TABLE payment_refunds ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_refunds FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON payment_refunds
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
