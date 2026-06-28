-- PMS-395: track billable minutes separately from worked (actual) minutes.
--
-- Until now a single `duration_minutes` was BOTH the worked time and the
-- billing basis, and rounding mutated that one figure to match the billing
-- increment. Split the concept into two persisted columns so billable time
-- can legitimately exceed or fall below worked time (minimum increments,
-- one update billed across several clients, internal absorption):
--
--   worked_minutes   - actual time spent (canonical going forward, never
--                      mutated by rounding).
--   billable_minutes - time billed. Defaults to the rounded worked time for
--                      billable entries; may be set independently.
--
-- `duration_minutes` is retained for one release as the source of truth for
-- existing consumers and tracks `worked_minutes`.

ALTER TABLE time_entries
    ADD COLUMN worked_minutes INTEGER,
    ADD COLUMN billable_minutes INTEGER;

-- Backfill: worked = the existing duration; billable = that duration for
-- entries flagged billable, else 0 (mirrors the prior timesheet rollup
-- `CASE WHEN is_billable THEN duration_minutes ELSE 0 END`).
UPDATE time_entries
SET worked_minutes = duration_minutes,
    billable_minutes = CASE WHEN is_billable THEN duration_minutes ELSE 0 END;
