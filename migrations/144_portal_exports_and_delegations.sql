-- PMS-729 phase 2 §7 slice D:
--   I15: portal contact data-export job queue
--   I18: portal contact-to-contact access delegation
--
-- Two independent tables that ship together because they are the two
-- new capabilities slice D lands.
--
-- portal_exports:
--   A contact requests a GDPR-style JSON bundle of their own
--   company's data. The route inserts a row here; the worker (an
--   `export_worker` cron job wired in a follow-up commit) picks up
--   `status = 'queued'` rows, generates the bundle, uploads it to
--   whatever attachment store is configured, and stamps
--   `signed_url` + `expires_at` + `status = 'ready'`. `expires_at`
--   is 7 days after the ready timestamp (D19); a poll after that
--   returns 410 Gone.
--
-- portal_delegations:
--   A delegator (portal contact) grants a delegatee (another portal
--   contact under the same company) access to act on their behalf.
--   Scope is a small JSONB blob today (`{"tickets": true,
--   "invoices": false, ...}`) so the surface can grow without a
--   schema migration; a plain read is the phase 2 minimum.
--   `expires_at` is optional (NULL = no expiry). `revoked_at` records
--   the moment the delegator or the tenant admin invalidates the
--   row; a revoked row stays for audit.

-- ============================================================================
-- portal_exports
-- ============================================================================

CREATE TABLE portal_exports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,

    status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'ready', 'failed', 'expired')),

    -- Bundle metadata (populated once the worker finishes).
    signed_url TEXT,
    -- 7-day TTL (D19) from ready_at; the poll route returns 410 after this.
    ready_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    -- On failure the worker persists a short error for the SPA to
    -- render; a caller cannot see agent-internal detail here (this is
    -- a customer-visible field).
    error_message TEXT,

    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_portal_exports_tenant_contact
    ON portal_exports(tenant_id, contact_id, requested_at DESC);

CREATE INDEX idx_portal_exports_queued
    ON portal_exports(tenant_id, requested_at)
    WHERE status = 'queued';

ALTER TABLE portal_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_exports FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON portal_exports
    USING (tenant_id::text = current_setting('app.current_tenant', TRUE));

COMMENT ON TABLE portal_exports IS
    'PMS-729 phase 2 §7 slice D / I15: GDPR-style data export jobs kicked off by portal contacts.';

-- ============================================================================
-- portal_delegations
-- ============================================================================

CREATE TABLE portal_delegations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Scope: both delegator and delegatee live under the same
    -- company_id. The FK on both stays hard because deleting either
    -- contact renders the delegation meaningless.
    delegator_contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    delegatee_contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,

    -- What the delegatee is allowed to do while acting for the
    -- delegator. `{}` = "nothing yet" (drafted grant); the SPA renders
    -- a checkbox row per scope key. Schema is small on purpose; growing
    -- adds a key inside the JSONB blob.
    scope JSONB NOT NULL DEFAULT '{}',

    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL = no expiry. A future task can lapse-expire without
    -- deleting the row (the audit trail matters).
    expires_at TIMESTAMPTZ,
    -- The moment the delegator or tenant admin invalidated the row.
    -- NULL = live. Kept for audit.
    revoked_at TIMESTAMPTZ,

    CONSTRAINT portal_delegations_different_contacts
        CHECK (delegator_contact_id <> delegatee_contact_id)
);

CREATE INDEX idx_portal_delegations_delegator
    ON portal_delegations(tenant_id, delegator_contact_id)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_portal_delegations_delegatee
    ON portal_delegations(tenant_id, delegatee_contact_id)
    WHERE revoked_at IS NULL;

ALTER TABLE portal_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_delegations FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON portal_delegations
    USING (tenant_id::text = current_setting('app.current_tenant', TRUE));

COMMENT ON TABLE portal_delegations IS
    'PMS-729 phase 2 §7 slice D / I18: portal contact-to-contact access delegation. Scope JSONB grows without a schema change.';
