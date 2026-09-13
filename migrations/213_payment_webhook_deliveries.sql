-- PMS-1182: every inbound payment webhook leaves a row, verified or refused.
--
-- Before this, a delivery left no trace here at all. `provider_webhook_handler`
-- resolved the tenant's provider, verified the body, dispatched and answered;
-- a refusal was an `AppError::Unauthorized` with nothing written down. So "the
-- provider never called us", "we refused it" and "we accepted it and it
-- matched no invoice" were indistinguishable from inside the application, and
-- all three present to the MSP as the same thing: the customer paid and the
-- invoice is still outstanding. That cost six real payments under PMS-1184,
-- where the only evidence anywhere was a row in PayPal's own dashboard saying
-- 401.
--
-- What is deliberately NOT stored is the body and the headers. A Stripe or
-- PayPal payload carries the payer's name and address, and the headers carry
-- the signature; what this table answers - did they call, when, which event,
-- and what did we do - needs neither, and keeping either would make this a
-- second home for a customer's personal data with no reader that needs it.
--
-- `event_type` and `event_id` are NULL on a refused delivery on purpose. They
-- would have to be read out of a body whose signature did not verify, and this
-- table must not become the place where unverified attacker-supplied text is
-- displayed to an admin as though the provider had said it.
CREATE TABLE payment_webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The provider the ROUTE names, known before anything is verified. Not a
    -- foreign key to `payment_gateway_configs`: the row records what arrived,
    -- and it has to survive the gateway being reconfigured or removed.
    provider VARCHAR(32) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    outcome VARCHAR(16) NOT NULL CHECK (
        outcome IN ('accepted', 'refused', 'ignored', 'failed')
    ),
    event_type VARCHAR(128),
    event_id VARCHAR(128),
    invoice_id UUID REFERENCES invoices(id) ON DELETE SET NULL,
    detail TEXT
);

-- The one read this serves: the most recent deliveries for a tenant, usually
-- narrowed to one provider.
CREATE INDEX idx_payment_webhook_deliveries_recent
    ON payment_webhook_deliveries (tenant_id, provider, received_at DESC);

ALTER TABLE payment_webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON payment_webhook_deliveries
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
