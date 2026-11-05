-- PMS-1644: `SlaService::evaluate_for_ticket` resolves the applicable SLA
-- policy as the ticket's own `sla_id` when set, else the tenant's default
-- policy, and now persists that resolved id onto `tickets.sla_id` (the
-- column the API surfaces) so a client reading the ticket back sees which
-- policy produced its due dates. Re-evaluation (status change) must keep
-- tracking the tenant's default when it changes, but once a default
-- resolution is written onto `sla_id` the column alone can no longer tell
-- "the client picked this policy" apart from "the evaluator filled this in
-- last time". This column carries that distinction so the evaluator keeps
-- re-deriving the default case while still honoring a real explicit pick.
--
-- Backfilled TRUE for every existing non-NULL `sla_id`: before this change
-- `evaluate_for_ticket` never wrote `sla_id` itself, so any row that already
-- has one got it from an explicit client assignment at creation.
ALTER TABLE tickets
    ADD COLUMN sla_id_explicit BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE tickets SET sla_id_explicit = TRUE WHERE sla_id IS NOT NULL;

COMMENT ON COLUMN tickets.sla_id_explicit IS
    'PMS-1644: TRUE when sla_id was set by an explicit client assignment rather than evaluate_for_ticket''s own default-policy fallback; governs whether re-evaluation keeps honoring sla_id or keeps re-resolving the tenant default.';
