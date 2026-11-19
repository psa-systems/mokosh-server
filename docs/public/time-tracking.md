# Time tracking

Time tracking separates client work from the MSP's own time, pins a work day to the technician's own timezone, and (when the Timesheets feature is on) enforces weekly review and approval.

## Client work vs employee time

Every time entry carries an `entry_kind` of `client` or `employee`.

- `client` entries represent billable or chargeable work for a customer. They must name a company; they may name a ticket, project, task or contract. A billing sweep reads only these.
- `employee` entries represent the MSP's own time: team meetings, training, administrative work, paid leave. They never name a ticket or a client company, and they are always non-billable.

The split is one column on one table, not two tables. This matters for reporting: the day's total across both kinds adds up to the technician's work day; a breakdown by kind shows how much of the day was client-facing. A query for "work a customer pays for" filters on `entry_kind = 'client'`.

## Timesheets

The Timesheets feature is tenant-gated. When it is on:

- Entries submit into a weekly timesheet.
- The weekly sheet goes through a submit-then-approve flow (technician submits, manager approves).
- An approved sheet locks its entries; editing requires rejecting and re-submitting.
- The approval audit is on the `/time-entries/{id}/approvals` route, which itself requires the Timesheets feature.

When the Timesheets feature is off:

- Entries exist and bill normally.
- There is no weekly submit. No approval step.
- The approvals endpoints are not mounted. A tenant with the feature off has no gate blocking billing.

Billing is unaffected by the feature's state. A tenant that bills by the entry (not the week) can leave Timesheets off.

## The work day is derived

A technician's work day is derived from their entry segments on that date in their own timezone, not stored directly. The derivation sums segment durations and groups them under the kind that logged them. This is why:

- Editing an entry's duration updates the day's total at the next read.
- An entry that starts late at night and ends after midnight splits across two work days along the technician's midnight, not UTC midnight.
- The "today" the technician sees is the "today" their tenant's timezone shows, not the server's.

## "Today" is the person's timezone

Every rule that refers to "today" is the person's local date. The server records UTC timestamps; the derivation and the UI resolve them against the user's timezone (or the tenant default if the user has not set one).

A tenant-level job, such as the overdue-invoice reminder worker, resolves "today" against the tenant's timezone, not UTC and not any one user's. This avoids a worker sending a 3 am reminder in the tenant's working hours because the server is in UTC.

## Work-day segments

A work day is composed of segments: ranges with a start, end and kind. A segment can be:

- A running timer (no end yet), one per technician at a time.
- A completed timer (end stamped when the timer stopped).
- A manually entered range (technician typed a start and end).
- An imported segment from another system (through `POST /work-days`).

A segment can be corrected: the technician edits a start, end, note, or kind, and the audit trail records the change with the old value, new value, who edited, and when. The correction does not retroactively un-bill a client entry it was part of; billing freezes at invoice issue.

## Timers

A technician has one running timer at a time. Starting a second timer stops the first. The timer carries a kind, work type, and optional ticket or project. Stopping the timer writes the finished segment to the day.

Timers are not required; a technician who works in blocks can type the segment range directly.

## Mileage

Mileage entries are a separate log alongside time, in the same "Log Time" surface on the SPA. They carry a date, distance and purpose, and they bill at the tenant's configured mileage rate.

## Work types

A work type names what the technician did. The tenant configures the list; each work type carries a flag for billable or not, and a default description for invoice lines.

## Who reads what

- A technician reads and writes their own entries.
- A manager reads every entry for everyone and approves timesheets.
- An admin or billing role reads entries for reporting and billing.
- A contact never reads time entries. Time data is staff-plane only.
