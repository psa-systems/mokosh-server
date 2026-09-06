-- MAPPS-459 (PMS-728 slice 3): per-tenant Bunyip-derived membership entitlement.
--
-- One row per tenant records the last known "is this instance paid up / current
-- on membership" signal from the Bunyip integration. `ensure_tenant_active`
-- consults it so a suspended tenant loses access on the next request without
-- flipping `tenants.status` (which is the operator-facing lifecycle column, not
-- a billing signal).
--
-- Design notes:
--
-- - `status` is a small enum. `unknown` is the seed value for a tenant that
--   has no integration configured yet OR whose latest webhook is older than the
--   grace window; the auth path treats `unknown` as pass-through so a broken
--   integration does not lock every customer out.
-- - `checked_at` is stamped by the webhook writer on every update; the auth
--   path uses `NOW() - checked_at` to compare against the grace window read
--   from `MOKOSH_ENTITLEMENT_GRACE_MINUTES` (default in application code).
-- - `expires_at` is the entitlement's own expiry, when Bunyip supplies one; the
--   auth path treats `expires_at < NOW()` as suspended regardless of `status`.
--   Nullable because not every webhook event carries an expiry hint.
--
-- The `tenants` table is the RLS-exempt isolation root; this table is per
-- tenant but read on the pre-auth / cross-tenant entitlement lookup path, so
-- it stays RLS-exempt as well (auth middleware runs the read on the migrator
-- pool with no tenant GUC). Access is gated by the small write surface: only
-- the webhook path may write.

CREATE TABLE tenant_membership_entitlements (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    status VARCHAR(16) NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('active', 'suspended', 'unknown')),
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NULL,
    -- Room for the webhook writer to log a machine-readable reason
    -- (e.g. "payment_failed", "cancelled") without changing schema. NULL for
    -- the seed / no-info state.
    reason VARCHAR(64) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Faster "which tenants recently checked in" queries for a future ops dashboard.
CREATE INDEX tenant_membership_entitlements_status_checked_idx
    ON tenant_membership_entitlements (status, checked_at DESC);
