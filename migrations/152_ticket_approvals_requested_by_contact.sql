-- PMS-937: contact-initiated approval requests need a way to
-- attribute the requester back to the portal contact who filed them.
--
-- Migration 066 shipped `requested_by_id UUID NOT NULL REFERENCES
-- users(id)` on the assumption that every approval came from an
-- agent user on the ticket. PMS-937 opens `POST
-- /api/v1/tickets/{id}/approvals/request` to portal contacts so a
-- customer can ask the MSP for formal sign-off directly, and the
-- requester is now a `contacts` row rather than a `users` row.
--
-- Shape:
--
--   * Add `requested_by_contact_id UUID REFERENCES contacts(id)`.
--     Nullable because staff-originated rows still populate
--     `requested_by_id` alone, and every existing row is
--     staff-originated (the contact-plane route is brand-new).
--   * Relax `requested_by_id` to nullable so a contact-plane insert
--     can leave it NULL without violating the legacy NOT NULL
--     constraint. Staff-plane inserts still populate it exactly as
--     before, and the new XOR CHECK below enforces that at least one
--     requester column is set on every row.
--   * Add `ticket_approvals_requester_xor` CHECK so a row is always
--     attributable to exactly one requester kind (agent user OR
--     portal contact, never both, never neither). Mirrors the
--     existing `ticket_approvals_approver_xor` shape on the
--     approver side.
--
-- Indexes:
--
--   * Partial `(tenant_id, requested_by_contact_id)` index so the
--     "every approval this portal contact filed" query lands as a
--     single scan without touching agent-originated rows.

ALTER TABLE ticket_approvals
    ADD COLUMN requested_by_contact_id UUID REFERENCES contacts(id);

ALTER TABLE ticket_approvals
    ALTER COLUMN requested_by_id DROP NOT NULL;

ALTER TABLE ticket_approvals
    ADD CONSTRAINT ticket_approvals_requester_xor
        CHECK ((requested_by_id IS NULL) <> (requested_by_contact_id IS NULL));

CREATE INDEX idx_ticket_approvals_requested_by_contact
    ON ticket_approvals(tenant_id, requested_by_contact_id)
    WHERE requested_by_contact_id IS NOT NULL;
