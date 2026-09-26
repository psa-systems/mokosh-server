-- PMS-1310: installed integrations per tenant, and what each one is allowed
-- to do.
--
-- Before this there was no integrations concept at all: a payment connection,
-- a contact connection and an RMM connection each got their own table, their
-- own `provider` CHECK, their own `is_active`, and their own sync interval.
-- That shape does not answer the question the integrations page exists to
-- answer, which is not "is Stripe connected" but "who does the invoicing".
-- Connecting Stripe says nothing about whether Stripe, Mokosh or Xero issues
-- the document, so every integration has to DECLARE its capabilities and the
-- tenant has to say which of them it is handing over.
--
-- `enabled_capabilities` is that declaration, and it is deliberately a subset
-- of what the provider supports rather than a boolean per integration: a
-- tenant can take Stripe for `payments` and keep issuing its own invoices even
-- though Stripe can do both. The supported set lives in
-- `src/modules/integrations/registry.rs` and NOT in this table, because it is a
-- property of the provider's implementation in this build and not of the
-- tenant's row; a copy here would let a row claim a capability the code cannot
-- serve. The subset rule is enforced in the service, which is the only writer.
--
-- No credential is in this table, and none may be added to it. Credentials go
-- through `crate::secrets::SecretProvider` under
-- `SecretKind::Integration { provider }` (PMS-967, PMS-1311), so an operator
-- can decide whether they live in Postgres or in Infisical. `config` is for
-- non-secret settings only. That separation is the whole reason integrations
-- waited for the secrets provider to land first.
--
-- ONE HOME PER CONNECTION. `payment_gateway_configs` (stripe, paypal) and
-- `contact_sync_connections` (google) already record whether those providers
-- are connected for a tenant, so this table must not also answer that while
-- they do. The registry records, per provider, which subsystem owns its
-- connection today, and `connect` / `disconnect` here refuse a provider whose
-- home is still elsewhere, naming it. PMS-1312 (Stripe) and PMS-1315
-- (contacts) each move one provider over, backfilling its rows in the same
-- change; until then no row exists for those providers at all, so the two
-- tables cannot disagree. `rmm_connections` is not in the provider list: RMM
-- is not one of the capabilities this subsystem arbitrates.

CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The discriminator the provider implementation is built from, the
    -- `contact_sync_connections.provider` shape. CHECKed to the set the
    -- registry declares, so a row cannot name a provider nothing can serve.
    -- Adding a provider means a migration here and an entry there.
    provider VARCHAR(32) NOT NULL CHECK (
        provider IN ('stripe', 'paypal', 'quickbooks', 'xero', 'google', 'microsoft')
    ),
    -- `disconnected` is its own outcome rather than a flavour of
    -- `not_connected`, for the `contact_sync_connections.sync_status` reason:
    -- an integration a tenant deliberately switched off is not one they never
    -- set up, and the capability set it was trusted with is worth keeping so
    -- reconnecting does not start from an empty page. `error` means the last
    -- exchange with the provider failed and `last_error` says how.
    status VARCHAR(20) NOT NULL DEFAULT 'not_connected' CHECK (
        status IN ('not_connected', 'connected', 'error', 'disconnected')
    ),
    -- Non-secret settings, per provider. A credential here is a defect; see
    -- the header.
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- The capabilities this tenant hands to this provider. A subset of the
    -- registry's supported set, enforced by the service.
    enabled_capabilities TEXT[] NOT NULL DEFAULT '{}',
    -- How often to poll, for a provider that polls. NULL means the provider
    -- does not poll, or the tenant has not overridden the registry's default.
    -- The floor mirrors `contact_sync_connections.sync_interval_minutes`: a
    -- one-minute poll against a third party is a rate limit waiting to happen.
    poll_interval_minutes INTEGER CHECK (
        poll_interval_minutes IS NULL OR poll_interval_minutes >= 5
    ),
    -- Who connected it, for the audit trail and for "ask them before you
    -- disconnect". SET NULL because an integration outlives the admin who set
    -- it up, the `contact_sync_connections.connected_by_user_id` reason.
    connected_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    connected_at TIMESTAMPTZ,
    disconnected_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One row per provider per tenant: the row IS the installation, so a
    -- second one would be a second answer to what this tenant delegated.
    UNIQUE (tenant_id, provider)
);

CREATE INDEX idx_integrations_tenant ON integrations (tenant_id);

-- Row-level security, fail closed. FORCE so the app pool (NOBYPASSRLS) cannot
-- escape it; the 024 / 038 sweeps ran long before this table existed, so the
-- same shape is attached explicitly (PMS-285).
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON integrations
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- PMS-1265: a table the app pool cannot see is a 500 on every read of it on a
-- deployment whose migrations run as an owner other than `mokosh_migrator`,
-- which staging's do.
GRANT SELECT, INSERT, UPDATE, DELETE ON integrations TO mokosh_app;

COMMENT ON TABLE integrations IS
    'Installed integrations per tenant (PMS-1310). One row per (tenant, provider); `enabled_capabilities` is the subset of the provider''s supported capabilities this tenant has delegated to it. Credentials are NOT here: they go through the secrets provider under SecretKind::Integration. The supported set and which subsystem owns each provider''s connection live in src/modules/integrations/registry.rs.';
