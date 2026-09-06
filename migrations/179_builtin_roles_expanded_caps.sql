-- PMS-936 (portal capability catalog expansion, foundation pass):
-- extend the built-in portal role capability arrays that migration 142
-- seeded so the roles the SPA renders out of the box gain the five new
-- granular caps this ticket introduces.
--
-- Migration 142 seeded three built-in rows per tenant (Billing Contact,
-- Support Contact, Read-Only); migrations are immutable so instead of
-- editing 142 we UPDATE the seeded rows here. Idempotent via the
-- append + de-dupe pattern: SELECT the existing capability array,
-- concatenate the new caps, then rebuild the array without dupes so a
-- re-run leaves the row unchanged.
--
-- Behaviour by role:
--   Billing Contact -> gains `invoices:download_pdf` and
--                      `quotes:download_pdf` (mirrors the "view + pay"
--                      posture: a role that already sees invoices +
--                      quotes should be able to grab the PDFs).
--   Support Contact -> gains `tickets:reopen`, `tickets:attach_file`,
--                      and `assets:report_issue` (mirrors the
--                      "raise + comment" posture with the higher-value
--                      escalation surfaces: reopening, attaching, and
--                      filing an asset-linked ticket).
--   Read-Only       -> unchanged. Read-only stays read-only; the new
--                      caps all mutate state (reopen / attach / new
--                      ticket / PDF stream) and would violate the
--                      role's contract.
--
-- The append + de-dupe expression uses `array(SELECT DISTINCT unnest(...))`
-- so a re-run of this migration on a tenant that somehow already has
-- one of the new caps in its array does not double it. `is_builtin =
-- TRUE` scopes the update so a tenant that renamed its built-in row
-- still gets patched, and a bespoke tenant-authored role that happens
-- to be named "Billing Contact" is not touched.

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY[
        'invoices:download_pdf',
        'quotes:download_pdf'
    ]::text[])
)
WHERE name = 'Billing Contact' AND is_builtin = TRUE;

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY[
        'tickets:reopen',
        'tickets:attach_file',
        'assets:report_issue'
    ]::text[])
)
WHERE name = 'Support Contact' AND is_builtin = TRUE;
