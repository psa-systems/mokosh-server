-- PMS-457 phase 1: saved custom-report definitions.
--
-- A `saved_reports` row stores a tenant-scoped report DEFINITION
-- (which entity to query, which columns + filters + grouping +
-- sort), not the result set. The runtime that compiles a row into a
-- SELECT and streams the rows ships separately as Phase 2; for now
-- the SPA's report-builder UI uses this surface to persist its
-- workflow ("name it, save it, come back to it tomorrow") while we
-- finish the compiler.
--
-- Definition is JSONB on purpose:
--   - filters: SPA-owned predicate tree, mirrors the existing
--     ticket / billing / time-entry list filters so the runtime can
--     reuse those service methods rather than hand-rolling a query
--     compiler;
--   - columns: ordered list of {field, header} so reordering an
--     export is a no-op edit at the DB layer;
--   - group_by / sort: small structured arrays.
-- The Phase 2 runtime validates these against a per-entity schema
-- it owns; the Phase 1 server stores them opaquely so the schema
-- can evolve without a migration.
--
-- `entity_type` is the discriminator the Phase 2 runtime uses to
-- pick which service to compile against (e.g. tickets, time_entries,
-- invoices). Free-text VARCHAR(50) so a future entity (assets,
-- projects) does not need a CHECK-widening migration; the runtime
-- rejects unknown values at execution time.
--
-- `is_shared` lets the author publish a report to the rest of the
-- tenant. Phase 1 only stores the flag; Phase 2 will surface shared
-- reports in the SPA's "Team reports" tab.
--
-- Phase 3 (scheduling + delivery): `scheduled_reports` rows reference
-- a `saved_report_id` and add cron + delivery target; out of scope
-- here.

CREATE TABLE saved_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Author. The "my reports" tab is keyed on this column. Shared
    -- reports still show their author so a viewer can ask the right
    -- person about a column choice.
    created_by_id UUID NOT NULL REFERENCES users(id),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    entity_type VARCHAR(50) NOT NULL,
    -- Predicate tree. Shape is owned by the Phase 2 compiler;
    -- stored opaquely here so the SPA can iterate without a server
    -- redeploy. Defaults to `{}` for a freshly-saved "blank
    -- canvas" report.
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Ordered column list (`[{field, header}, ...]`). Same opaque
    -- posture as `filters`.
    columns JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Group-by + sort. Both small structured arrays; opaque at the
    -- DB layer.
    group_by JSONB NOT NULL DEFAULT '[]'::jsonb,
    sort JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_shared BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Owner's "my reports" tab: one index scan per tenant + user.
CREATE INDEX idx_saved_reports_owner
    ON saved_reports(tenant_id, created_by_id);

-- Shared "team reports" tab: partial so non-shared rows do not
-- consume the index.
CREATE INDEX idx_saved_reports_shared
    ON saved_reports(tenant_id, is_shared)
    WHERE is_shared = true;

-- Filter by entity: "show me every report against `tickets`" is the
-- query the entity-page sidebar fires when offering "saved reports".
CREATE INDEX idx_saved_reports_entity
    ON saved_reports(tenant_id, entity_type);
