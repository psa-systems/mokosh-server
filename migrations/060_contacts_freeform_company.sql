-- PMS-402: accept a freeform company on contacts.
--
-- A contact no longer has to point at an existing CRM `companies` row. It may
-- instead carry a typed-in (freeform) company label, or neither (a bare name
-- plus phone). Two changes:
--
--   1. Drop the NOT NULL on `contacts.company_id` so a contact can exist with
--      no CRM company link. The `REFERENCES companies(id) ON DELETE CASCADE`
--      FK and the existing indexes (`idx_contacts_company`, `idx_contacts_type`)
--      stay valid on a nullable column.
--   2. Add a nullable `company_name VARCHAR(255)` column holding the stored
--      freeform label. When `company_id` is set the application leaves this
--      NULL (the CRM name is authoritative via the read-side LEFT JOIN, which
--      aliases `companies.name` to the same `company_name` output column via
--      COALESCE(co.name, c.company_name)). Enforcement that the two are
--      mutually exclusive lives in the application layer, not a DB CHECK.

ALTER TABLE contacts ALTER COLUMN company_id DROP NOT NULL;

ALTER TABLE contacts ADD COLUMN company_name VARCHAR(255);
