-- PMS-483: ticket-note attachments storage upgrade.
--
-- The `ticket_attachments` table has existed since migration 005 but
-- had no upload route, no portal posture, and required a non-NULL
-- `uploaded_by_id` (which assumed every uploader was a tenant user).
--
-- PMS-483 ships the upload / download / delete surface on both the
-- agent tree (`/api/v1/tickets/{id}/notes/{note_id}/attachments`) and
-- the portal tree (`/api/v1/portal/tickets/{id}/notes/{note_id}/...`).
-- A portal contact is NOT a user row, so the schema needs to record
-- contact-side authorship symmetric with how PMS-468 widened
-- `ticket_notes.created_by_contact_id`.
--
-- Two changes:
--
--   * Add `created_by_contact_id UUID NULL REFERENCES contacts(id) ON
--     DELETE SET NULL`. Populated on portal uploads; NULL on agent
--     uploads (which keep their `uploaded_by_id` populated instead).
--   * Relax `uploaded_by_id` to NULL. Portal uploads have no user
--     row to point at; the (uploaded_by_id IS NOT NULL) +
--     (created_by_contact_id IS NOT NULL) invariant is enforced at
--     the application layer so the right authorship column is set
--     per origin.

ALTER TABLE ticket_attachments
    ADD COLUMN created_by_contact_id UUID
        REFERENCES contacts(id) ON DELETE SET NULL;

ALTER TABLE ticket_attachments
    ALTER COLUMN uploaded_by_id DROP NOT NULL;

-- The portal-side "is this contact allowed to read it?" check joins
-- attachments -> ticket_notes -> tickets -> companies; the existing
-- ticket index covers that path. The new partial index targets the
-- "feed of all attachments uploaded by this contact" portal query
-- the SPA can later use to render a "your uploads" rail.
CREATE INDEX idx_ticket_attachments_contact
    ON ticket_attachments(tenant_id, created_by_contact_id)
    WHERE created_by_contact_id IS NOT NULL;
