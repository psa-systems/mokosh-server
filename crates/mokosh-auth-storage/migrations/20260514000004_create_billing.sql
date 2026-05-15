-- Billing surface (read-only in this round; Stripe writes are deferred).
--
-- Three tables:
--   billing_tiers   - the catalogue of plans. Maintained by ops.
--   subscriptions   - one row per tenant; what plan + lifecycle status.
--   invoices        - historical invoices (table only; populated by a
--                     future Stripe webhook handler).
--
-- See docs/mokosh-fixes/05-billing.md.

CREATE TABLE mokosh_auth.billing_tiers (
    tier_key            TEXT         PRIMARY KEY,
    display_name        TEXT         NOT NULL,
    description         TEXT         NOT NULL DEFAULT '',
    monthly_price_cents INTEGER      NOT NULL DEFAULT 0,
    trial_days          INTEGER      NOT NULL DEFAULT 0,
    seat_count          INTEGER      NOT NULL DEFAULT 0,
    slot_limit          INTEGER,
    sort_order          INTEGER      NOT NULL DEFAULT 0,
    features            TEXT[]       NOT NULL DEFAULT '{}',
    is_public           BOOLEAN      NOT NULL DEFAULT TRUE,
    stripe_price_id     TEXT
);

CREATE TABLE mokosh_auth.subscriptions (
    tenant_id              UUID         PRIMARY KEY REFERENCES public.tenants(id) ON DELETE CASCADE,
    tier_key               TEXT         NOT NULL REFERENCES mokosh_auth.billing_tiers(tier_key),
    status                 TEXT         NOT NULL DEFAULT 'trialing'
                                          CHECK (status IN ('trialing', 'active', 'past_due', 'canceled', 'lifetime')),
    trial_end              TIMESTAMPTZ,
    current_period_end     TIMESTAMPTZ,
    cancel_at_period_end   BOOLEAN      NOT NULL DEFAULT FALSE,
    grace_period_end       TIMESTAMPTZ,
    stripe_customer_id     TEXT,
    stripe_subscription_id TEXT,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE mokosh_auth.invoices (
    id              TEXT         PRIMARY KEY,
    tenant_id       UUID         NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    amount_cents    INTEGER      NOT NULL,
    currency        TEXT         NOT NULL DEFAULT 'usd',
    status          TEXT         NOT NULL,
    hosted_pdf_url  TEXT,
    period_start    TIMESTAMPTZ  NOT NULL,
    period_end      TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_invoices_tenant_created ON mokosh_auth.invoices (tenant_id, created_at DESC);

-- Seed the default catalogue. Idempotent on tier_key.
INSERT INTO mokosh_auth.billing_tiers
    (tier_key, display_name, description, monthly_price_cents, trial_days,
     seat_count, slot_limit, sort_order, features, is_public)
VALUES
    ('free',     'Free',      'Get started with the basics.',                    0,   0,  1,   3,  10,
     ARRAY['Up to 3 members', 'Email + password auth', 'Audit log (7 days)'], TRUE),
    ('starter',  'Starter',   'For small teams just getting going.',          1900,  14, 10,  25,  20,
     ARRAY['Up to 10 members', 'OIDC SSO', 'MFA', '30-day audit log'], TRUE),
    ('pro',      'Pro',       'Everything in Starter, plus more headroom.',   4900,  14, 50, 200,  30,
     ARRAY['Unlimited members', 'Step-up MFA', 'Trusted devices', '90-day audit log', 'Priority support'], TRUE),
    ('enterprise','Enterprise','Custom contracts, SLAs, and SCIM.',                0,  30,  0,  NULL, 40,
     ARRAY['Everything in Pro', 'SCIM provisioning', 'Custom SLAs', 'Dedicated support'], TRUE)
ON CONFLICT (tier_key) DO NOTHING;
