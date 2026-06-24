-- PMS-471 / PMS-453 phase 2b: scheduled dashboard delivery.
--
-- PMS-453 phase 1 shipped the per-user `saved_dashboards` table. The
-- widget-rendering SPA surface (phase 2a) is in flight separately;
-- this migration adds the schedule + worker queue so a user can mark
-- a saved dashboard "deliver this weekly to my email". The worker
-- materialises the dashboard's layout JSONB into a simple text /
-- HTML snapshot and enqueues an `email` row into `notifications`,
-- which the existing DispatcherWorker drains with SMTP + retry
-- backoff (mirrors the scheduled_reports pattern from PMS-478).
--
-- The schedule row is owned by the same user that owns the parent
-- saved_dashboard (saved dashboards are private to their owner;
-- there is no shared-dashboard concept today), and the schedule
-- inherits that ownership: ON DELETE CASCADE on both `dashboard_id`
-- and `user_id` so removing a dashboard or user also removes its
-- schedules.
--
-- Reader / writer: src/modules/dashboards/service.rs
-- Worker:          src/modules/dashboards/worker.rs

CREATE TABLE scheduled_dashboards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dashboard_id UUID NOT NULL REFERENCES saved_dashboards(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Standard cron expression (cron crate, 6-field form with
    -- seconds). Validated at the API surface via
    -- `utils::validation::validate_cron`.
    cron_expr VARCHAR(100) NOT NULL,
    -- Phase 2b only ships email; the column is here so a future
    -- in-app digest or SMS surface lands without a schema migration.
    -- CHECK keeps the surface tight today.
    channel VARCHAR(20) NOT NULL DEFAULT 'email' CHECK (channel IN ('email')),
    -- Optional override; when NULL the worker delivers to the owning
    -- user's email (resolved from `users.email`).
    recipient_email VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ NOT NULL,
    -- NULL on success; populated with the failure reason on the most
    -- recent tick that errored. The worker still advances
    -- `next_run_at` on failure so a single bad row does not block
    -- the next cadence.
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot-path index for the worker tick: pull `is_active = true` rows
-- whose next_run_at has come due, ordered by next_run_at, FOR
-- UPDATE SKIP LOCKED. Partial so a tenant that disables every
-- schedule keeps its rows out of the worker's scan.
CREATE INDEX idx_scheduled_dashboards_next_run_active
    ON scheduled_dashboards(next_run_at)
    WHERE is_active = true;

CREATE INDEX idx_scheduled_dashboards_tenant
    ON scheduled_dashboards(tenant_id);

CREATE INDEX idx_scheduled_dashboards_dashboard
    ON scheduled_dashboards(dashboard_id);
