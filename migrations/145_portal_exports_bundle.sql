-- PMS-729 phase 2 §7 slice D / I15 follow-up: bundle payload column.
--
-- Slice D shipped the queue table + the API contract but deferred the
-- worker that actually builds the JSON bundle. That worker lands in
-- src/modules/portal/export_worker.rs; this migration gives it a place
-- to persist the finished payload.
--
-- The bundle is a small JSON document (contact profile + own-company
-- tickets + notes + invoices + quotes) capped by natural row counts, so
-- keeping it in-row rather than pushing it to the attachment store
-- keeps deployment simple: no per-tenant object storage bucket needed
-- for phase 2, and the payload is protected by the same RLS the
-- surrounding row already carries.
--
-- Nullable: rows in queued / running / failed status have no payload,
-- and rows that have expired past their 7-day TTL will be scrubbed by
-- a follow-up cron job (D19). Setting to NULL costs zero storage on
-- the toast pages.

ALTER TABLE portal_exports
    ADD COLUMN bundle_json JSONB;

COMMENT ON COLUMN portal_exports.bundle_json IS
    'PMS-729 phase 2 §7 slice D / I15: the finished JSON bundle. Populated by the export worker when the row transitions to `ready`; blanked when it expires past `expires_at`.';
