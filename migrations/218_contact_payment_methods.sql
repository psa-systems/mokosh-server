-- MAPPS-674: a portal contact's saved payment methods.
--
-- The contact types their card once into the payment provider's own hosted
-- page (Stripe Checkout in `mode: 'setup'`); the provider returns a
-- PaymentMethod id and attaches it to a Customer on THEIR side. Mokosh
-- stores the id plus the four fields the list view needs to render
-- without a per-render API round trip: brand, last4, exp_month, exp_year.
-- The CARD DATA never touches mokosh: no PAN, no CVV, no full expiry
-- string, no billing address. What we hold is a stable reference plus a
-- display digest, which is the same posture Shopify / Squarespace / any
-- Stripe-integrated SaaS holds.
--
-- Rows are inserted by the webhook receiver: the SetupIntent completes,
-- the provider fires `checkout.session.completed` with `mode = setup`,
-- and the receiver reads the session metadata (`contact_id`, `tenant_id`)
-- we stamped at mint time to know which portal contact this belongs to.
-- Removal detaches on the provider side FIRST (`PaymentMethod.detach`),
-- then deletes the row: symmetric, so a future auto-charge cannot
-- resurface the card the contact told the portal to forget.
--
-- One default per contact is enforced by the partial UNIQUE index below,
-- not by a check constraint: setting a NEW default runs `UPDATE ... SET
-- is_default = TRUE` on the picked row and `UPDATE ... SET is_default =
-- FALSE` on every other row of that contact in one transaction, so an
-- inconsistent state cannot commit even under concurrent writes.
--
-- The provider column mirrors `payment_gateway_configs.provider`'s CHECK
-- constraint, so a row on a tenant that has retired their gateway keeps
-- its provider name and the removal path can still call the provider's
-- detach. When a provider is added there (PayPal Reference Transactions
-- is the next candidate; see MAPPS-674's follow-up note), it gets a row
-- shape here too.

CREATE TABLE contact_payment_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    -- Matches payment_gateway_configs.provider (`stripe`, `paypal`).
    -- Enforced at the application layer against ProviderKind::LEGAL_VALUES
    -- and at the DB layer through the FK on payment_gateway_configs when
    -- one is added (not today: a card belongs to a contact, and a tenant
    -- CAN retire the gateway config while keeping the contact's stored
    -- reference alive so the detach path still works).
    provider VARCHAR(30) NOT NULL CHECK (provider IN ('stripe', 'paypal')),
    -- The provider's stable reference for this card. Stripe: `pm_...`.
    -- PayPal: the billing-agreement token, when that surface lands.
    provider_pm_id VARCHAR(255) NOT NULL,
    -- Card brand as the provider spells it: `visa`, `mastercard`, etc.
    -- Stored lowercased; the SPA humanises it for display.
    brand VARCHAR(30) NOT NULL DEFAULT '',
    -- Last four digits of the PAN. Kept as a fixed-width string rather
    -- than an integer so a leading zero survives round-tripping.
    last4 CHAR(4) NOT NULL DEFAULT '',
    -- Two-digit month (1..12) and four-digit year. The expiry-reminder
    -- worker (MAPPS-674 follow-up: BUNYIP-style 30-day-out scheduler)
    -- reads these to decide who to email.
    exp_month SMALLINT NOT NULL CHECK (exp_month BETWEEN 1 AND 12),
    exp_year SMALLINT NOT NULL CHECK (exp_year BETWEEN 2000 AND 2100),
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A card is uniquely identified within a tenant by the provider's own
-- reference: the same `pm_...` can never appear twice against one
-- contact, and cross-contact re-use inside a tenant would be a provider
-- bug we should surface not silently duplicate.
CREATE UNIQUE INDEX idx_contact_payment_methods_provider_pm
    ON contact_payment_methods (tenant_id, provider, provider_pm_id);

-- At most one default per contact. The transaction `set_default` runs
-- flips one row TRUE and every other FALSE inside a single BEGIN; the
-- partial index catches any concurrent write that would leave two rows
-- TRUE at once.
CREATE UNIQUE INDEX idx_contact_payment_methods_one_default
    ON contact_payment_methods (tenant_id, contact_id)
    WHERE is_default = TRUE;

CREATE INDEX idx_contact_payment_methods_contact
    ON contact_payment_methods (tenant_id, contact_id);

ALTER TABLE contact_payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_payment_methods FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contact_payment_methods
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON contact_payment_methods TO mokosh_app;
