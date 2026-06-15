-- PMS-323: enforce "at most one default per tenant" at the DATABASE layer for
-- the five tenant-scoped lookup tables that carry an `is_default` flag:
-- tax_rates, ticket_statuses, ticket_priorities, ticket_queues, project_types.
--
-- Single-default is currently guaranteed ONLY by the service layer: every
-- create/update method clears the prior default (UPDATE ... SET is_default =
-- FALSE WHERE tenant_id = $1 [AND id <> $2]) BEFORE setting the new row, all
-- inside one begin_with_tenant transaction. That holds only as long as every
-- writer goes through those methods; a direct SQL write or a future code path
-- that forgets the clear could leave two defaults in one tenant, and the read
-- paths (LIMIT 1) would then resolve the default non-deterministically.
--
-- A partial unique index on (tenant_id) WHERE is_default is the idiomatic
-- Postgres single-default guard: it lets every non-default row coexist while
-- permitting at most one default per tenant. The existing clear-then-set
-- service flow satisfies it without change because, at the instant the new row
-- is set true, no other row in that tenant is true (the immediate, non-deferred
-- index is checked at statement end, after the clear has run in the same txn).
--
-- Before each index is built, defensively collapse any pre-existing duplicate
-- defaults to a single row per tenant so the index builds cleanly. tax_rates
-- has no sort_order column, so it is deduped by (created_at, id); the other
-- four keep the lowest sort_order as the surviving default.

-- ============================================================================
-- tax_rates (no sort_order column: order by created_at, id).
-- ============================================================================
UPDATE tax_rates t
SET is_default = FALSE
WHERE t.is_default
  AND t.id <> (
    SELECT d.id FROM tax_rates d
    WHERE d.tenant_id = t.tenant_id AND d.is_default
    ORDER BY d.created_at, d.id
    LIMIT 1
  );

CREATE UNIQUE INDEX idx_tax_rates_one_default ON tax_rates (tenant_id) WHERE is_default;

-- ============================================================================
-- ticket_statuses.
-- ============================================================================
UPDATE ticket_statuses t
SET is_default = FALSE
WHERE t.is_default
  AND t.id <> (
    SELECT d.id FROM ticket_statuses d
    WHERE d.tenant_id = t.tenant_id AND d.is_default
    ORDER BY d.sort_order, d.created_at, d.id
    LIMIT 1
  );

CREATE UNIQUE INDEX idx_ticket_statuses_one_default ON ticket_statuses (tenant_id) WHERE is_default;

-- ============================================================================
-- ticket_priorities.
-- ============================================================================
UPDATE ticket_priorities t
SET is_default = FALSE
WHERE t.is_default
  AND t.id <> (
    SELECT d.id FROM ticket_priorities d
    WHERE d.tenant_id = t.tenant_id AND d.is_default
    ORDER BY d.sort_order, d.created_at, d.id
    LIMIT 1
  );

CREATE UNIQUE INDEX idx_ticket_priorities_one_default ON ticket_priorities (tenant_id) WHERE is_default;

-- ============================================================================
-- ticket_queues.
-- ============================================================================
UPDATE ticket_queues t
SET is_default = FALSE
WHERE t.is_default
  AND t.id <> (
    SELECT d.id FROM ticket_queues d
    WHERE d.tenant_id = t.tenant_id AND d.is_default
    ORDER BY d.sort_order, d.created_at, d.id
    LIMIT 1
  );

CREATE UNIQUE INDEX idx_ticket_queues_one_default ON ticket_queues (tenant_id) WHERE is_default;

-- ============================================================================
-- project_types.
-- ============================================================================
UPDATE project_types t
SET is_default = FALSE
WHERE t.is_default
  AND t.id <> (
    SELECT d.id FROM project_types d
    WHERE d.tenant_id = t.tenant_id AND d.is_default
    ORDER BY d.sort_order, d.created_at, d.id
    LIMIT 1
  );

CREATE UNIQUE INDEX idx_project_types_one_default ON project_types (tenant_id) WHERE is_default;
