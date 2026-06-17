-- PMS-394: make ticket association optional with a named general-work category.
--
-- Ticket/project association on time_entries is already nullable at the schema
-- level, but a ticketless entry was previously just "unattributed" with no way
-- to classify true overhead (admin tasks, calls, reception work) for reporting.
-- Add an explicit work_category axis alongside the mandatory work_type_id so a
-- ticketless entry is classifiable rather than merely empty.
--
-- Taxonomy is the three-value set ticketed | project | general. The default is
-- 'ticketed' so the common case (time logged against a ticket) needs no extra
-- field. Backfill existing rows from the presence of ticket_id / project_id:
-- general when neither is set, ticketed when a ticket is set, else project.
ALTER TABLE time_entries
    ADD COLUMN work_category VARCHAR(20) DEFAULT 'ticketed'
    CHECK (work_category IN ('ticketed', 'project', 'general'));

UPDATE time_entries
SET work_category = CASE
    WHEN ticket_id IS NOT NULL THEN 'ticketed'
    WHEN project_id IS NOT NULL THEN 'project'
    ELSE 'general'
END;
