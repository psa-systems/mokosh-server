-- PMS-950: a day of an employee's time is a thing the system holds.
--
-- With timesheets on (PMS-943), an employee clocks in for the day and the
-- items worked that day are read against that day. The day is the unit, and
-- it covers the whole working day rather than only the parts a client pays
-- for. Nothing recorded that a day had started: a timesheet is a grouping of
-- `time_entries` by week, and `active_timers` (migration 006) is one open
-- timer against one work item, which measures a task and not a day.
--
-- A day is not a row. It is derived from its segments: a `work` segment opens
-- at clock-in and closes at clock-out, and lunch is a `break` segment between
-- two `work` segments, which is "model lunch as a clock-out" without a second
-- concept. A day row would be a second home for facts the segments already
-- hold (still open, total clocked, total on break) and the only one that can
-- disagree with them.
--
-- `date` is the day the segment belongs to, supplied by the client the way
-- `time_entries.date` is, and a segment keeps it across midnight so a night
-- shift stays on the day it started.
--
-- Numbered 188 and not 135: `mokosh-contact-login` holds 135 through 187,
-- all applied on staging, and PMS-965 renumbers the file that was never
-- applied, which would have been this one.

CREATE TABLE work_day_segments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    date DATE NOT NULL,
    kind VARCHAR(10) NOT NULL CHECK (kind IN ('work', 'break')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);

-- One open segment per person, whatever its kind or date. The same shape as
-- `active_timers.UNIQUE(user_id)`: the service checks and refuses with a 409,
-- and this index closes the race between two clock-ins that both saw nothing
-- open. Partial, because a person has many closed segments.
CREATE UNIQUE INDEX idx_work_day_segments_open
    ON work_day_segments (user_id)
    WHERE ended_at IS NULL;

-- The day view reads one person's one day.
CREATE INDEX idx_work_day_segments_day
    ON work_day_segments (tenant_id, user_id, date);

-- Fail-closed RLS, the shape every tenant-scoped table carries since
-- 038_rls_fail_closed.sql and that `tests/rls_coverage.rs` enforces.
ALTER TABLE work_day_segments ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_day_segments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON work_day_segments;
CREATE POLICY tenant_isolation ON work_day_segments
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
