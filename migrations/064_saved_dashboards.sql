-- PMS-453 (Phase 1): saved dashboards.
--
-- A `saved_dashboards` row holds a per-user dashboard definition - a
-- name and a JSONB `layout` blob the SPA reads to know which widgets to
-- mount and in what positions. The blob shape is owned by the SPA
-- (widget keys, grid coordinates, filter scope per widget); the server
-- stores it verbatim so a UI change can ship without a schema
-- migration. The default-flag column lets the user pin one of their
-- dashboards as the post-login landing page.
--
-- Scheduled report delivery (Phase 2 of PMS-453) is intentionally NOT
-- in this migration. That work needs a `scheduled_reports` table plus a
-- background worker that drains cron expressions; both are tracked as a
-- follow-up under PMS-453.

CREATE TABLE saved_dashboards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Owner. Dashboards are private to the user that authored them; a
    -- future "share with team" feature is tracked separately.
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    -- The full layout definition. SPA-owned shape; server is opaque.
    layout JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Pin one dashboard as the user's default post-login landing page.
    -- At most one is_default per (tenant_id, user_id) is enforced by the
    -- partial unique index below; the application sets is_default = false
    -- on any previously-default row in the same transaction as the new
    -- promotion.
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-tenant per-user index so a user's own dashboards list is one
-- index scan. (tenant_id, user_id) keeps the index narrow and matches
-- the WHERE clause `list_my_dashboards` will use.
CREATE INDEX idx_saved_dashboards_owner ON saved_dashboards(tenant_id, user_id);

-- At most one default dashboard per (tenant_id, user_id). Partial so
-- non-default rows do not consume the unique slot.
CREATE UNIQUE INDEX idx_saved_dashboards_one_default
    ON saved_dashboards(tenant_id, user_id)
    WHERE is_default = true;
