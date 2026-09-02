-- PMS-919: deleting a company unlinks the rows that were already allowed to
-- have no company, instead of blocking on them.
--
-- Every FK to `companies` was declared with no `ON DELETE` clause, so they all
-- default to NO ACTION. For the columns that are `NOT NULL` that is forced by
-- the data model: an invoice, a payment, a time entry, a ticket, a contract, a
-- quote, an asset or a mileage entry has no valid company-less state, and those
-- deliberately keep blocking. Destroying financial and operational history
-- because someone tidied a client list is the one outcome this must not enable.
--
-- For the columns below it was an omission. Each is nullable, so a row with no
-- company is ALREADY a valid state that the application produces on its own;
-- the FK blocked the delete anyway and forced the user to hand-clear rows the
-- schema was happy to leave company-less. MAPPS-574 is the report: a company
-- was undeletable because of a single project.
--
-- This is migration 110's argument, applied to the columns it did not cover:
--
--     SET NULL, not RESTRICT: a company-less contact has been a valid state
--     since PMS-402, and RESTRICT would make deleting a company impossible
--     until every contact was hand-moved.
--
-- Unlike 110 this is the primary path, not a backstop. `contacts` needed
-- service-side work first because `contacts.company_name` mirrors the link
-- (PMS-806/PMS-812). None of the five columns here carries a mirror -
-- `contacts.company_name` is the only such column in the schema - so the FK
-- action is the whole mechanism and `delete_company` does not pre-null them.
--
-- Two nullable columns are deliberately NOT included, because their block is a
-- real decision rather than an accident:
--
--   * `credential_vault.company_id`. Nulling it leaves encrypted secret
--     material owned by nothing (`asset_id` may also be NULL), unreachable from
--     every company- and asset-scoped view, never rotated and never deleted.
--     Cascading destroys secrets silently. Both are worse than making the
--     operator decide, so it keeps blocking.
--   * `tenants.own_company_id`. PMS-413 makes this the anchor every general /
--     overhead time entry is attributed to. Nulling it would not fail here, it
--     would fail later as a NOT NULL violation on `time_entries` the next time
--     someone logged overhead time. `delete_company` refuses it explicitly
--     instead, so the reason arrives at the point of the decision.

DO $$
DECLARE
    target RECORD;
    fk_name TEXT;
BEGIN
    FOR target IN
        SELECT * FROM (VALUES
            -- A project without a client is a valid internal project.
            ('projects',            'company_id'),
            -- An appointment without a company is an internal meeting.
            ('appointments',        'company_id'),
            -- A running timer not yet attributed to a client.
            ('active_timers',       'company_id'),
            -- An unmapped RMM device; this is the state before mapping, too.
            ('rmm_device_mappings', 'company_id'),
            -- Deleting a parent promotes its sub-companies to top level.
            ('companies',           'parent_company_id')
        ) AS t(tbl, col)
    LOOP
        -- Resolve the constraint's REAL name rather than assuming
        -- `<table>_<column>_fkey` (110): a DROP CONSTRAINT IF EXISTS on a wrong
        -- guess silently no-ops and leaves the old action in place next to the
        -- new one. A miss is an exception, never a skip.
        SELECT con.conname INTO fk_name
        FROM pg_constraint con
        WHERE con.contype = 'f'
          AND con.conrelid = format('public.%I', target.tbl)::regclass
          AND con.confrelid = 'public.companies'::regclass
          AND con.conkey = ARRAY[(
              SELECT a.attnum FROM pg_attribute a
              WHERE a.attrelid = format('public.%I', target.tbl)::regclass
                AND a.attname = target.col
          )]::smallint[];

        IF fk_name IS NULL THEN
            RAISE EXCEPTION 'no foreign key found on %(%) -> companies(id)',
                target.tbl, target.col;
        END IF;

        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', target.tbl, fk_name);

        -- DEFERRABLE INITIALLY IMMEDIATE preserves the PMS-648 property that
        -- the tenant-data import can `SET CONSTRAINTS ALL DEFERRED`; a
        -- constraint added by a migration after 088 defaults to NOT DEFERRABLE
        -- and would break that import.
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (%I) '
            'REFERENCES companies(id) ON DELETE SET NULL '
            'DEFERRABLE INITIALLY IMMEDIATE',
            target.tbl, fk_name, target.col);
    END LOOP;
END $$;
