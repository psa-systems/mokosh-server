-- MAPPS-998 slice 1: per-user saved views for the Tickets list.
--
-- A row here is the operator's reusable "my morning view": a captured
-- combination of filters, search text and sort. v1 is per-user. The owner
-- `user_id` keys the row so each operator has their own list; cross-user
-- reads are impossible because the service scopes every query on
-- `(tenant_id, user_id)` and RLS adds the tenant half, so a cross-tenant id
-- answers 404 (no existence oracle) rather than returning the row.
--
-- `filter` is JSONB rather than one column per axis because the Tickets list
-- grows filter axes faster than the schema should: PMS-1310 added `asset_id`
-- and `team_id` without migrating this row's shape, MAPPS-997 just added
-- `queue_id`, and spelling each in a column pins the client to a server
-- version. The SPA writes exactly what its querystring builder would write
-- (`search`, `status_id`, `priority_id`, `queue_id`, ...); the server reads
-- it back verbatim and lets the regular `TicketFilter` validator refuse an
-- unknown key when the view is applied. So a view saved today still works
-- after a future axis lands, and a view carrying a now-retired axis is still
-- readable - the axis just does nothing.
--
-- `sort` is also JSONB for the same reason: the shape is `{ "key": "...",
-- "direction": "asc" | "desc" }`, and `TICKETS_RECENT_SORT`'s allow-list is
-- what refuses an unknown key.
--
-- `(tenant_id, user_id, name)` is unique: two "Morning queue" views for one
-- operator read as the control being broken. The index on
-- `(tenant_id, user_id)` is what the list endpoint reads from, in `name ASC`
-- order so dashboards render deterministically.

CREATE TABLE ticket_saved_views (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    filter     JSONB NOT NULL DEFAULT '{}'::jsonb,
    sort       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id, name)
);

CREATE INDEX idx_ticket_saved_views_owner
    ON ticket_saved_views (tenant_id, user_id);

ALTER TABLE ticket_saved_views ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ticket_saved_views
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- PMS-1265: a table the app pool cannot see is a 500 on every read of it on
-- a deployment whose migrations run as an owner other than `mokosh_migrator`,
-- which staging's do.
GRANT SELECT, INSERT, UPDATE, DELETE ON ticket_saved_views TO mokosh_app;

COMMENT ON TABLE ticket_saved_views IS
    'Per-user saved views for the Tickets list (MAPPS-998). `filter` and `sort` are JSONB so adding a new filter axis does not need a migration; the SPA writes exactly what its querystring builder would write, and the regular TicketFilter / sort allow-lists refuse an unknown key when the view is applied.';
