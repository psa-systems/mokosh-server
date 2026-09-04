-- PMS-937: extend the built-in Support Contact portal role with the
-- two new granular caps this ticket introduces so the role the SPA
-- renders out of the box gains contact-owned ticket editing and the
-- contact-initiated approval-request surface.
--
-- Migrations 142 and 150 are immutable so this migration UPDATEs the
-- seeded rows in place using the same append + de-dupe pattern as
-- migration 150. Idempotent via `array(SELECT DISTINCT unnest(...))`
-- so a re-run against a row that somehow already carries one of the
-- new caps does not double it.
--
-- Role scope:
--   Support Contact -> gains `tickets:edit_own` and
--                      `tickets:request_approval`. Mirrors the
--                      role's raise + comment + escalate posture; a
--                      Support Contact who can open a ticket should
--                      be able to correct a typo in the title and
--                      ask the MSP for formal approval on a
--                      resolution or out-of-scope work.
--   Billing Contact -> unchanged. Neither cap is billing-shaped;
--                      Billing Contact does not open or triage
--                      tickets.
--   Read-Only       -> unchanged. Both new caps mutate state (edit
--                      the row, insert an approval row) and would
--                      violate the role's read-only contract.
--
-- `is_builtin = TRUE` scopes the update so a tenant that renamed its
-- built-in row still gets patched, and a bespoke tenant-authored
-- role that happens to be named "Support Contact" is not touched.

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY[
        'tickets:edit_own',
        'tickets:request_approval'
    ]::text[])
)
WHERE name = 'Support Contact' AND is_builtin = TRUE;
