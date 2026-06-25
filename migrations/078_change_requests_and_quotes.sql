-- PMS-484: parent tables for the change_request + quote approval
-- targets that PMS-470 widened the polymorphic approvals surface to
-- accept.
--
-- PMS-470 routed `/change-requests/{id}/approvals` and
-- `/quotes/{id}/approvals` but the handlers short-circuited with 400
-- because the parent rows the route-layer `assert_parent_exists`
-- check needs did not exist in the schema yet. This migration ships
-- the minimal `(id, tenant_id, ...)` tables those checks need.
--
-- Scope is deliberately minimal. The approval flow needs only:
--
--   * the parent to exist within the tenant (the `assert_parent_exists`
--     check), and
--   * enough fields for the SPA to label the row when it renders the
--     approval timeline (`title`, `requested_by_id`, `summary`,
--     `status`).
--
-- A richer change-management / sales workflow is its own follow-up;
-- this migration is intentionally NOT trying to be the final shape of
-- either entity. The columns chosen mirror what the ticket-approvals
-- surface already reads off `tickets` so the SPA can render both
-- entities through the existing components without per-entity casing.

CREATE TABLE change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    requested_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    -- Free-text inside a CHECK so a future workflow engine can widen
    -- the state machine without a fresh migration. The four shipped
    -- values cover the lifecycle the approval flow cares about
    -- (draft -> submitted -> approved | rejected).
    status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'submitted', 'approved', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant-scoped scan, mirrors the `tickets(tenant_id)` index posture.
CREATE INDEX idx_change_requests_tenant ON change_requests(tenant_id);

CREATE TABLE quotes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    requested_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    -- Money lives at the `quote_lines` follow-up; storing the headline
    -- total + currency here keeps the v1 approval timeline informative
    -- without forcing the line-item migration to land first.
    total_cents BIGINT NOT NULL DEFAULT 0,
    currency CHAR(3) NOT NULL DEFAULT 'USD',
    status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'submitted', 'approved', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_quotes_tenant ON quotes(tenant_id);
