-- PMS-729 finalize: restore the ticket.note_added org-identity body.
--
-- Migration 104 (main, PMS-761 / MAPPS-429) rewrote the ticket-note
-- body to use `{{org_name}}` + `{{contact_line}}` so a client-facing
-- update names the MSP and offers a contact line. This branch's own
-- migration 110 (`notification_templates_branding`) then rewrote the
-- SAME row to a branding-footer shape (`{{msp_name}} ... {{msp_support_email}}`),
-- silently reverting 104's change because 110's WHERE clause matches
-- on the original migration-021 subject and 104 does not touch the
-- subject.
--
-- Both migrations are immutable once applied, so this migration steps
-- forward: repair every tenant whose ticket.note_added body still
-- shows 110's shape and put back the org-identity keys 104 wanted.
-- Idempotent WHERE guard so operators who have hand-customised the
-- template are left alone.
--
-- The subject stays as 110 left it (`[{{msp_name}}][{{ticket_number}}] {{ticket_title}}`) -
-- it's a strict improvement on the ticket-number-only original and the
-- MSP prefix is what a client with multiple MSP relationships needs
-- to attribute the mail.

BEGIN;

UPDATE notification_templates SET
    body_text = E'{{org_name}} has added an update to ticket {{ticket_number}}:\n\n{{content}}\n\n{{contact_line}}\n',
    updated_at = NOW()
WHERE event_type = 'ticket.note_added'
  AND channel_type = 'email'
  AND body_text = E'A new update has been added to ticket {{ticket_number}}:\n\n{{content}}\n\n-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n';

COMMIT;
