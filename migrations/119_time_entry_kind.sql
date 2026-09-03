-- PMS-942: say whether a time entry is a client's work or the employee's.
--
-- One table held both. A timesheet is an HR record belonging to the MSP; time
-- billed to a ticket or a project belongs to a client engagement. Nothing in
-- the schema said which a row was, so approval, billing and reporting rules
-- could not differ between them without every query restating the distinction.
--
-- Not two tables. PMS-943 requires a day's timesheet to break down ticket
-- work, project work and administrative time, so the employee's day and the
-- client's work are two axes over the same fact. Splitting the rows would mean
-- unioning them back together in every rollup.
--
-- Not `company_id IS NULL` either. PMS-413 (migration 062) already created one
-- `internal` company per tenant and pointed `tenants.own_company_id` at it, and
-- MAPPS-243 attributes a General entry to it, so today's overhead time names a
-- company. An inferred axis would make every one of those rows wrong; a named
-- column tolerates them and lets a query say which kind it wants.

ALTER TABLE time_entries
    ADD COLUMN entry_kind VARCHAR(20) NOT NULL DEFAULT 'client'
    CHECK (entry_kind IN ('client', 'employee'));

-- The backfill is exact rather than a heuristic. "No ticket means internal"
-- would reclassify a billable client call logged without a ticket as the MSP's
-- own time, moving hours off the client; `company_id = own_company_id` is the
-- signal PMS-413 established for precisely this question.
--
-- The ticket / project / task / contract conditions are what keep the backfill
-- from writing a row that the constraint below would then reject, aborting the
-- migration mid-flight and crash-looping the server on start. A row attributed
-- to the internal company but carrying client work stays `client`, which is the
-- conservative answer.
UPDATE time_entries te
SET entry_kind = 'employee'
FROM tenants t
WHERE t.id = te.tenant_id
  AND te.company_id = t.own_company_id
  AND te.ticket_id IS NULL
  AND te.project_id IS NULL
  AND te.task_id IS NULL
  AND te.contract_id IS NULL;

-- Employee time may now name no company at all, which is what stops the
-- own-company from being load-bearing. It is a nullable FK to a deletable row,
-- so today an employee whose tenant has no internal company cannot log overhead
-- time: the SPA disables the General option (mokosh-apps time.rs), and
-- `stop_timer` 400s with "Cannot stop timer without an inferable company_id".
-- Existing rows keep the company they were attributed to; nothing is rewritten.
ALTER TABLE time_entries
    ALTER COLUMN company_id DROP NOT NULL;

-- The invariants. A client's work names the client. The employee's own time
-- carries no client-side association.
--
-- `is_billable` is deliberately NOT in this constraint. It defaults TRUE, so an
-- overhead entry logged before this migration may well be flagged billable, and
-- a CHECK covering it would abort on that row. The service refuses it on new
-- entries and the invoice feed excludes employee time by kind, which is where
-- it matters.
ALTER TABLE time_entries
    ADD CONSTRAINT time_entries_client_names_a_company
    CHECK (entry_kind <> 'client' OR company_id IS NOT NULL);

ALTER TABLE time_entries
    ADD CONSTRAINT time_entries_employee_time_has_no_client_work
    CHECK (
        entry_kind <> 'employee'
        OR (ticket_id IS NULL AND project_id IS NULL
            AND task_id IS NULL AND contract_id IS NULL)
    );

CREATE INDEX idx_time_entries_kind ON time_entries (tenant_id, entry_kind);

COMMENT ON COLUMN time_entries.entry_kind IS
    'PMS-942: `client` is work booked against a customer and eligible for invoicing; `employee` is the MSP''s own time (administrative, overhead, breaks) and never reaches a client invoice.';
