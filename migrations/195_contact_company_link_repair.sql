-- PMS-1069: give every `contacts.company_id` back its `contact_companies` row.
--
-- PMS-806 made `company_id` a MIRROR of the primary link and the service
-- re-derives it from `contact_companies` on every contact update, so a contact
-- carrying a `company_id` with no link loses that company on the first edit of
-- any field, with no error and no audit entry naming a removed link.
--
-- Migration 108 backfilled the link table once, at migration time. Three
-- writers outside `modules/contacts` have inserted `contacts.company_id` on its
-- own ever since (email intake's auto-created sender, the tenant portal-admin
-- contact, the dev seeder), so every contact they wrote is in that state on any
-- database running this code. The writers now go through
-- `ensure_primary_company_link`; this repairs the rows already written.
--
-- Same statement as 108's backfill, plus the `NOT EXISTS` guard: a contact that
-- already has links keeps exactly the links it has, whichever is primary. The
-- partial unique index `idx_contact_companies_one_primary` is what makes that
-- guard load-bearing rather than decorative.
INSERT INTO contact_companies (tenant_id, contact_id, company_id, title, is_primary, sort_order)
SELECT c.tenant_id, c.id, c.company_id, c.title, TRUE, 0
FROM contacts c
WHERE c.company_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM contact_companies l WHERE l.contact_id = c.id
  );
