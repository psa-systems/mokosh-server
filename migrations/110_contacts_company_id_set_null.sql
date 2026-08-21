-- PMS-812: deleting a company unlinks its contacts instead of deleting them.
--
-- `contacts.company_id` was created `ON DELETE CASCADE` (004_contacts.sql), and
-- PMS-402 dropped its NOT NULL without touching the action, so deleting a
-- company still destroyed every contact whose mirror pointed at it. PMS-806
-- made `company_id` a mirror of the PRIMARY entry in `contact_companies`, so a
-- contractor linked to clients A (primary) and B lost their whole `contacts`
-- row - and the B link with it - when A was deleted. Nothing about B justified
-- that.
--
-- SET NULL, not RESTRICT: a company-less contact has been a valid state since
-- PMS-402, and RESTRICT would make deleting a company impossible until every
-- contact was hand-moved.
--
-- This is the backstop, not the primary path. `ContactService::delete_company`
-- deletes the company's `contact_companies` rows and recomputes the mirrors
-- first, so an app-driven delete leaves nothing for this action to null out.
-- The action covers a direct SQL delete and any row whose mirror outlives its
-- link.

-- Drop by the constraint's REAL name rather than the assumed
-- `contacts_company_id_fkey`: a `DROP CONSTRAINT IF EXISTS` on a wrong guess
-- would silently no-op and leave the CASCADE in place alongside the new FK.
DO $$
DECLARE
    fk_name TEXT;
BEGIN
    SELECT con.conname INTO fk_name
    FROM pg_constraint con
    JOIN pg_class child ON child.oid = con.conrelid
    JOIN pg_class parent ON parent.oid = con.confrelid
    WHERE con.contype = 'f'
      AND child.oid = 'public.contacts'::regclass
      AND parent.oid = 'public.companies'::regclass
      AND con.conkey = ARRAY[(
          SELECT a.attnum FROM pg_attribute a
          WHERE a.attrelid = 'public.contacts'::regclass AND a.attname = 'company_id'
      )]::smallint[];

    IF fk_name IS NULL THEN
        RAISE EXCEPTION 'no foreign key found on contacts(company_id) -> companies(id)';
    END IF;

    EXECUTE format('ALTER TABLE contacts DROP CONSTRAINT %I', fk_name);
END $$;

-- DEFERRABLE INITIALLY IMMEDIATE preserves the PMS-648 property that the
-- tenant-data import can `SET CONSTRAINTS ALL DEFERRED`; a constraint added by
-- a migration after 088 defaults to NOT DEFERRABLE and would break that import.
ALTER TABLE contacts
    ADD CONSTRAINT contacts_company_id_fkey
    FOREIGN KEY (company_id) REFERENCES companies(id)
    ON DELETE SET NULL
    DEFERRABLE INITIALLY IMMEDIATE;
