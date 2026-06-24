-- PMS-478 / PMS-457 phase 3: scheduled report delivery.
--
-- PMS-457 phase 1 shipped the saved-report definitions; PMS-477
-- (phase 2) added the executor. Phase 3 turns "the operator
-- explicitly clicked Run" into "this report goes out weekly to
-- alice@". The schedule rows are owned by the requesting user (a
-- shared report can be scheduled by any tenant member; each member
-- has their own schedule + cadence).
--
-- The worker reads one of these rows per tick, runs the saved
-- report's compiler-executor, renders the result set to CSV, and
-- enqueues an `email` row into `notifications` so the existing
-- DispatcherWorker (notifications/worker.rs) does the SMTP + retry
-- backoff. That keeps the scheduled-reports worker focused on
-- "materialise + advance the schedule" instead of re-implementing
-- transport.
--
-- The `cron_expr` is validated by `utils::validation::validate_cron`
-- (cron crate, 6-field format with seconds). `next_run_at` is set
-- by the service on create (Schedule::upcoming on NOW) and bumped
-- by the worker after each run.
--
-- Reader / writer: src/modules/saved_reports/service.rs
-- Worker: src/modules/saved_reports/worker.rs

CREATE TABLE scheduled_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The definition the worker compiles + runs. CASCADE because a
    -- schedule pointing at a deleted report can never produce useful
    -- output again.
    saved_report_id UUID NOT NULL REFERENCES saved_reports(id) ON DELETE CASCADE,
    -- The owner of this schedule. Identity used by the execute call
    -- (so shared-report visibility rules apply per-owner) and
    -- defaulted into `recipient_email` when the override is unset.
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Standard cron expression. Validated at the API surface with
    -- `utils::validation::validate_cron`.
    cron_expr VARCHAR(100) NOT NULL,
    -- Phase 3 only ships email; the column is here so a future SMS /
    -- in-app delivery does not need a schema migration. CHECK keeps
    -- the surface tight today.
    channel VARCHAR(20) NOT NULL DEFAULT 'email' CHECK (channel IN ('email')),
    -- Output format. Phase 3 only ships CSV; same forward-looking
    -- pattern as `channel`.
    format VARCHAR(10) NOT NULL DEFAULT 'csv' CHECK (format IN ('csv')),
    -- Optional override; when NULL the worker delivers to the owning
    -- user's email (resolved from `users.email`).
    recipient_email VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ NOT NULL,
    -- NULL on success; populated with the failure reason on the most
    -- recent tick that errored. The worker still advances
    -- `next_run_at` on failure so a single bad row does not block the
    -- next cadence.
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot-path index for the worker tick: pull `is_active = true` rows
-- whose next_run_at has come due, ordered by next_run_at, FOR UPDATE
-- SKIP LOCKED. Partial so a tenant that disables every schedule
-- keeps its rows out of the worker's scan.
CREATE INDEX idx_scheduled_reports_next_run_active
    ON scheduled_reports(next_run_at)
    WHERE is_active = true;

CREATE INDEX idx_scheduled_reports_tenant
    ON scheduled_reports(tenant_id);

CREATE INDEX idx_scheduled_reports_saved_report
    ON scheduled_reports(saved_report_id);
