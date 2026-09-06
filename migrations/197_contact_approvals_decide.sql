-- PMS-1084: a contact decides the approvals addressed to it.
--
-- Two parts. `ticket_approvals.decided_by_id` is a `users` FK, so a
-- decision made on the contact plane had nowhere to record who made it
-- (the retired portal left it NULL). `decided_by_contact_id` is the
-- contact-side twin, nullable, `ON DELETE SET NULL` like
-- `approver_contact_id` (migration 143): a decided row outlives the
-- contact and reads as "decided by a removed contact" rather than
-- vanishing. No XOR with `decided_by_id`: a pending row carries
-- neither, and the service writes exactly one of the two.
--
-- And the built-in Support Contact role gains `approvals:decide`, the
-- capability that gates `GET /approvals/pending` and
-- `POST /approvals/{id}/decision` on the contact plane. Same append +
-- de-dupe shape as migration 180, scoped on `is_builtin` for the same
-- reason. Billing Contact and Read-Only are unchanged: deciding
-- mutates the row, and the approvals an MSP addresses to a customer
-- are about tickets and change requests, the Support Contact's
-- surface.

ALTER TABLE ticket_approvals
    ADD COLUMN decided_by_contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL;

COMMENT ON COLUMN ticket_approvals.decided_by_contact_id IS
    'PMS-1084: the portal contact who decided the row on the contact plane. NULL while pending and on every staff decision, which records decided_by_id instead.';

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY['approvals:decide']::text[])
)
WHERE name = 'Support Contact' AND is_builtin = TRUE;
