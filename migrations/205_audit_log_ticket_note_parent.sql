-- PMS-974: a ticket's change history includes the edits made to its notes.
--
-- A note edit is audited as `entity_type = 'ticket_notes'` with the note's id
-- in `entity_id`, so the per-record history read (`entity_type = 'tickets'
-- AND entity_id = <ticket>`) never saw it. The read now also selects the
-- tenant's `ticket_notes` rows whose snapshot names the ticket; the ticket id
-- lives inside the JSONB snapshot, so this partial expression index is what
-- keeps that arm off a scan of every note edit in the tenant.
CREATE INDEX idx_audit_log_ticket_note_parent
    ON audit_log ((new_values ->> 'ticket_id'))
    WHERE entity_type = 'ticket_notes';
