-- PMS-406: index the team-scoped ticket queries.
--
-- Wiring the `team_id` ticket filter (GET /api/v1/tickets?team_id=...) and the
-- team-scoped dashboard aggregates (GET /reports/dashboard?team_id=...) means
-- every team-scoped list and KPI query filters `WHERE tenant_id = $1 AND
-- team_id = $n`. Without a composite index those queries fall back to the
-- per-tenant index plus a heap filter on team_id. Add a covering composite
-- index so they stay fast as ticket volume grows, following the per-tenant
-- index precedent set across the schema (e.g. idx_ticket_categories_tenant).
--
-- `team_id` is nullable (a ticket need not belong to a team); a plain B-tree
-- still serves the equality predicate the filter emits, so no partial index is
-- needed.

CREATE INDEX IF NOT EXISTS idx_tickets_tenant_team ON tickets (tenant_id, team_id);
