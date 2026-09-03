-- PMS-729 phase 2 §7 slice D / I15 follow-up: surface truncation to the SPA.
--
-- Post-code-review finding #7 capped the export worker's per-section
-- fetch at 5k tickets / 20k notes / 10k invoices / 5k quotes to keep a
-- runaway tenant from OOMing the worker. The bundle itself carries a
-- `truncated: true` top-level marker plus a `section_totals` count map so
-- a client fetching the bundle can tell it is incomplete, but the SPA's
-- export page shows only the status row and never fetches the bundle
-- until the user clicks download. Without hoisting these two values to
-- the row, a truncated bundle looks identical to a complete one on the
-- portal page.
--
-- This migration adds `bundle_truncated` (BOOLEAN NOT NULL DEFAULT FALSE)
-- and `bundle_section_totals` (JSONB NULLABLE), populated by the worker
-- when the bundle is generated. Both are read by the status endpoint and
-- rendered on the portal export page as an inline warning when
-- truncated. Nullable `section_totals` matches the shape used inside the
-- bundle (an object with per-section counts) and is left NULL on failed
-- or expired rows where no counting ever ran.
--
-- No RLS change needed: policies already cover the whole row via
-- (tenant_id, contact_id).

ALTER TABLE portal_exports
    ADD COLUMN bundle_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN bundle_section_totals JSONB;

COMMENT ON COLUMN portal_exports.bundle_truncated IS
    'PMS-729 phase 2 §7 slice D / I15 follow-up: TRUE when the worker capped any per-section fetch and the resulting bundle is incomplete. Rendered as a warning on the SPA export page.';
COMMENT ON COLUMN portal_exports.bundle_section_totals IS
    'PMS-729 phase 2 §7 slice D / I15 follow-up: per-section total row counts observed at bundle time (`{tickets, notes, invoices, quotes}`). Rendered alongside the truncated warning so the customer can see what was skipped.';
