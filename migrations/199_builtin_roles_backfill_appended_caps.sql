-- PMS-1118: bring every built-in portal role up to the set it should
-- hold today.
--
-- `TenantService::seed_builtin_portal_roles` inserted the three built-in
-- roles for a NEW tenant with the capability sets migration 171 shipped,
-- while migrations 179 (PMS-936), 180 (PMS-937) and 197 (PMS-1084) each
-- UPDATEd the rows that existed when they ran. A tenant created after any
-- of them therefore holds a Support Contact without `tickets:reopen`,
-- `tickets:attach_file`, `assets:report_issue`, `tickets:edit_own` or
-- `tickets:request_approval`, and a Billing Contact without the two PDF
-- caps. The code seed now binds the same sets the migrations produced
-- (`contact_portal::capabilities::BUILTIN_ROLES`, pinned against the
-- migrations by a test); this migration repairs the rows already seeded
-- short. Same append + de-dupe shape as 179, scoped on `is_builtin` so a
-- bespoke role that borrowed a built-in name is not touched. Read-Only
-- gained nothing since 171 and is listed for completeness only.

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY[
        'invoices:read', 'invoices:pay', 'quotes:read', 'quotes:accept',
        'notifications:read', 'settings:manage_own',
        'invoices:download_pdf', 'quotes:download_pdf'
    ]::text[])
)
WHERE name = 'Billing Contact' AND is_builtin = TRUE;

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY[
        'tickets:read', 'tickets:write', 'tickets:comment', 'kb:read',
        'notifications:read', 'settings:manage_own',
        'tickets:reopen', 'tickets:attach_file', 'assets:report_issue',
        'tickets:edit_own', 'tickets:request_approval',
        'approvals:decide'
    ]::text[])
)
WHERE name = 'Support Contact' AND is_builtin = TRUE;

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY[
        'tickets:read', 'invoices:read', 'quotes:read', 'contracts:read',
        'assets:read', 'projects:read', 'kb:read', 'notifications:read'
    ]::text[])
)
WHERE name = 'Read-Only' AND is_builtin = TRUE;
