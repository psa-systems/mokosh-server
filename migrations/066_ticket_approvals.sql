-- PMS-451 phase 1: per-ticket approval requests.
--
-- A `ticket_approvals` row tracks a request for sign-off on a ticket
-- (e.g. before closing high-cost work, before applying a change). The
-- requester is the agent currently on the ticket; the decider is
-- either a named user (assign-by-id) or any user holding a specific
-- role (assign-by-role, evaluated at decision time). Either field can
-- be set but not both - the CHECK constraint enforces XOR so a
-- malformed insert is rejected at the schema layer rather than the
-- application.
--
-- Phase 2 (generic polymorphic approvals across tickets / change
-- requests / quotes / time entries) is intentionally not in this
-- migration. The phase-1 ticket-scoped table keeps the query plan
-- single-index-narrow and lets the SPA's ticket detail render the
-- approval timeline in a single round trip; the polymorphic surface
-- folds tickets in as a special case once the second consumer
-- (change requests) is real.

CREATE TABLE ticket_approvals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    -- The agent who asked for approval. Always populated; FK to users
    -- so a deleted agent surfaces as "unknown requester" in the SPA
    -- through a LEFT JOIN rather than a foreign-key panic.
    requested_by_id UUID NOT NULL REFERENCES users(id),
    -- Specific approver (assign-by-id). NULL when the request is
    -- scoped by role instead. NOT a strong FK because users get
    -- deleted; the SPA renders a missing user as "unknown approver".
    approver_user_id UUID REFERENCES users(id),
    -- Role-based approver (assign-by-role). Free-text VARCHAR so a
    -- tenant can target a custom role; standard PSA roles (admin,
    -- manager, finance) cover the typical case.
    approver_role VARCHAR(50),
    -- Outcome. `pending` until decided. `cancelled` covers the case
    -- where the requester rescinds before any approver weighs in.
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    -- Why the requester is asking. Optional but encouraged; the SPA
    -- renders this in the approval card so the approver does not have
    -- to read the whole ticket to know what's being asked.
    notes TEXT,
    -- Recorded with the decision. Lets the approver leave a reason
    -- on a reject, or a "yes please proceed" on an approve.
    decision_notes TEXT,
    -- User who clicked approve / reject. NULL while pending.
    decided_by_id UUID REFERENCES users(id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ,
    -- Either approver_user_id OR approver_role must be set (XOR).
    -- Both-set or neither-set is a malformed approval. Phrased as the
    -- positive XOR rather than the negative double-IS-NULL so the
    -- intent is readable at the schema layer.
    CONSTRAINT ticket_approvals_approver_xor
        CHECK ((approver_user_id IS NULL) <> (approver_role IS NULL))
);

-- Tenant + ticket scan: "show me every approval on ticket X".
CREATE INDEX idx_ticket_approvals_ticket
    ON ticket_approvals(tenant_id, ticket_id);

-- Pending-queue scan for assign-by-user: "show user U their pending
-- decisions". Partial so non-pending rows do not consume the index.
CREATE INDEX idx_ticket_approvals_user_pending
    ON ticket_approvals(tenant_id, approver_user_id)
    WHERE status = 'pending' AND approver_user_id IS NOT NULL;

-- Pending-queue scan for assign-by-role: "show user U the pending
-- decisions for any role U holds". Partial for the same reason.
CREATE INDEX idx_ticket_approvals_role_pending
    ON ticket_approvals(tenant_id, approver_role)
    WHERE status = 'pending' AND approver_role IS NOT NULL;
