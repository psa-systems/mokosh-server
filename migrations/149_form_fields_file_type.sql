-- Widen the `form_fields.field_type` CHECK to include 'file'.
--
-- The portal form builder now supports a `file` field the customer can
-- attach binary content to at submit time. The JSON payload has no
-- channel for binary uploads; the SPA still sends the form JSON to
-- POST /portal/forms/{id}/submit as before, gets back the freshly-
-- created ticket_id, and uploads each `file`-typed field's contents
-- to the ticket's first note via the existing per-note multipart
-- endpoint (`/portal/tickets/{id}/notes/{id}/attachments`). No
-- schema for `file`-field storage itself; the ticket-note attachment
-- pipeline is the durable record.
--
-- Migrations are immutable, so widening the CHECK constraint is a
-- new migration rather than an edit of 100.

ALTER TABLE form_fields
    DROP CONSTRAINT form_fields_field_type_check,
    ADD CONSTRAINT form_fields_field_type_check
        CHECK (field_type IN ('text', 'textarea', 'email', 'date', 'select', 'boolean', 'file'));
