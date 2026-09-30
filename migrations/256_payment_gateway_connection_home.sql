-- PMS-1312: whether a payment provider is connected for a tenant moves into
-- `integrations`.
--
-- Migration 252 created that table and deliberately left Stripe and PayPal out
-- of it: `payment_gateway_configs.is_active` already answered "is this provider
-- switched on for this tenant", and a second answer to one question is the one
-- thing guaranteed to end in two rows disagreeing. The registry
-- (`src/modules/integrations/registry.rs`) recorded that with a
-- `ConnectionHome::Elsewhere` entry per provider naming this issue, and
-- `IntegrationsService` refused `connect`, `disconnect` and a capability change
-- for them, so until now no row existed for either provider at all.
--
-- What moves is exactly that one fact. Everything else about a gateway stays
-- where it is: the credential stays in the secret provider under
-- `SecretKind::PaymentGateway` (PMS-967, PMS-968), and `is_test_mode`,
-- `client_display_name` and `min_partial_amount` stay on the gateway row,
-- because they are settings of a payment gateway and not of an installation in
-- general. That is why this is a backfill and not a table merge.
--
-- After this migration the reads that decide whether a customer sees a Pay Now
-- button, which provider mints a checkout session, and which tenant a webhook
-- delivery resolves against, all filter on `integrations.status = 'connected'`.
-- `payment_gateway_configs.is_active` is left in place as a ONE-WAY MIRROR: it
-- is written by the single writer that sets the status
-- (`integrations::connection::set_payment_connection`) and read by nothing in
-- this build. It is kept for one release rather than dropped because a
-- deployment that rolls back to the previous image reads it as its only answer,
-- and a column dropped out from under that image is every gateway silently off
-- (worse: a checkout the customer completes and nothing records). The release
-- that drops it is the one after every deployment has taken this one.
--
-- The status mapping, and what it deliberately does not claim:
--
--   is_active = TRUE  -> 'connected'
--   is_active = FALSE -> 'not_connected'
--
-- An inactive row could mean "set up and never switched on" or "switched off
-- deliberately", and nothing stored distinguishes them, so it maps to the
-- status that asserts neither. `disconnected` would additionally need a
-- `disconnected_at`, and inventing a timestamp for an event that may never have
-- happened is worse than the coarser status. For an active row `connected_at`
-- is the gateway row's own `updated_at`, which is the last moment its active
-- flag could have been written; it is the closest true thing available and is
-- not a recorded connect event. `connected_by_user_id` stays NULL for the same
-- reason: the gateway row never recorded who.
--
-- `authorize_net` rows are skipped. That value is in
-- `payment_gateway_configs.provider`'s CHECK and in nothing else - no provider
-- implementation, and not in `integrations.provider`'s CHECK - so a row for it
-- here would name a provider this subsystem cannot describe.
--
-- No `set_config('app.current_tenant', ...)` around the INSERT, although
-- `integrations` is `FORCE ROW LEVEL SECURITY`: migrations run as a BYPASSRLS
-- role (`mokosh_migrator` per `src/db/provision.rs`, and staging's `mokosh`
-- owner), which is the same assumption every cross-tenant backfill in this
-- directory already makes, migration 198's contact-mirror repair included.

INSERT INTO integrations (
    tenant_id,
    provider,
    status,
    config,
    enabled_capabilities,
    poll_interval_minutes,
    connected_by_user_id,
    connected_at,
    created_at,
    updated_at
)
SELECT
    g.tenant_id,
    g.provider,
    CASE WHEN g.is_active THEN 'connected' ELSE 'not_connected' END,
    '{}'::jsonb,
    -- `payments` alone, never the provider's whole supported set: a gateway row
    -- exists because somebody wanted to take card payments, and enabling
    -- `invoicing` on their behalf would claim this tenant handed their invoice
    -- issuing to Stripe, which nothing in this build implements and nobody
    -- asked for.
    ARRAY['payments']::text[],
    -- Neither provider polls, so no interval applies.
    NULL,
    NULL,
    CASE WHEN g.is_active THEN g.updated_at ELSE NULL END,
    g.created_at,
    NOW()
FROM payment_gateway_configs g
WHERE g.provider IN ('stripe', 'paypal')
ON CONFLICT (tenant_id, provider) DO NOTHING;

COMMENT ON COLUMN payment_gateway_configs.is_active IS
    'RETIRED by PMS-1312 and kept for one release. Whether a payment provider is connected for a tenant lives in `integrations.status`; this column is a one-way mirror written only by integrations::connection::set_payment_connection so a rolled-back image still serves, and read by nothing. Dropped in the release after every deployment has taken migration 256.';
