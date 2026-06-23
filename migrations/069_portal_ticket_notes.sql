-- PMS-449 phase 1: portal ticket comments.
--
-- `ticket_notes` already carries `note_type='public'` for the
-- customer-visible track. Add `created_by_contact_id` so portal-
-- originated notes record which contact authored them, distinct
-- from the agent-attribution `created_by_id`.
--
-- Posture: `created_by_id` stays NOT NULL. Portal-originated notes
-- set `created_by_id` to the tenant's fallback admin (same pattern
-- as `create_portal_ticket`) AND populate `created_by_contact_id`
-- with the real author. That lets the SPA render the comment as
-- coming from the customer without changing the shared
-- `TicketNote.created_by_id` DTO field (an Option migration ripples
-- across mokosh-types and every consumer). The `created_by_id`
-- fallback row is still useful: it tells the agent UI which admin
-- the system attributed inbound comments to.
--
-- ON DELETE SET NULL on the contact FK so retiring a contact does
-- not cascade-delete their notes; the comment thread stays intact
-- and the SPA renders the orphan rows as "(deleted contact)".

ALTER TABLE ticket_notes
    ADD COLUMN created_by_contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL;

-- Index for "list every comment this contact ever posted" (the
-- portal's own activity feed in a later phase, and the agent UI's
-- "show me all comments from this customer"). Partial because the
-- column is opt-in - agent-authored notes leave it NULL.
CREATE INDEX idx_ticket_notes_contact
    ON ticket_notes(tenant_id, created_by_contact_id)
    WHERE created_by_contact_id IS NOT NULL;
