-- Backfill the missing `team_id` column on `appointments`.
--
-- Commit f8d4a0a3 ("feat(calendar): PMS-791 phase 3 - appointments carry
-- team_id + cross-tenant guard") added Rust code that INSERTs and SELECTs
-- `appointments.team_id`, and its message claimed the column existed since
-- migration 008. That is not true: `008_calendar.sql` defines
-- `on_call_schedules.team_id` but NOT `appointments.team_id`, and no later
-- migration adds one. Every `create_appointment` / `list_appointments` /
-- `appointments_in_range` call therefore 500s with:
--
--     column "team_id" of relation "appointments" does not exist
--
-- Add the column with the shape f8d4a0a3 expected: nullable UUID, FK to
-- `teams(id)`, `ON DELETE SET NULL` so retiring a team preserves the
-- appointments it once routed to (matches the `on_call_schedules.team_id`
-- FK shape). RLS on `appointments` is unaffected (already enabled since
-- 038's tenantful-tables loop covers this table via `tenant_id`).

ALTER TABLE appointments
    ADD COLUMN team_id UUID REFERENCES teams(id) ON DELETE SET NULL;

-- List / filter path in `CalendarService::list_appointments` scopes on
-- (tenant_id, team_id); an index keeps the team-filtered read cheap on a
-- box with tens of thousands of appointments.
CREATE INDEX idx_appointments_team ON appointments(tenant_id, team_id);
