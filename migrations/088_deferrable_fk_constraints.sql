-- PMS-648: make every foreign key DEFERRABLE INITIALLY IMMEDIATE so the
-- tenant-data import (`src/modules/data_transfer`) can `SET CONSTRAINTS ALL
-- DEFERRED` inside its transaction and wipe + reload a tenant's tables in ANY
-- order. The schema has FK cycles (companies.primary_contact_id <->
-- contacts.company_id), self-referential FKs (tasks.parent_task_id), and
-- excluded tables that reference load tables (credential_vault -> assets), none
-- of which can be satisfied by a per-statement topological order. Deferring the
-- checks to COMMIT makes the whole wipe-and-replace order-independent.
--
-- INITIALLY IMMEDIATE means the default per-statement checking is UNCHANGED for
-- every normal operation; only a transaction that explicitly runs
-- `SET CONSTRAINTS ALL DEFERRED` (i.e. the import) defers them. This is idempotent
-- (skips constraints that are already deferrable), so a re-run is a no-op.
--
-- NOTE: constraints added by FUTURE migrations default to NOT DEFERRABLE. Any
-- new foreign key that the import path must cross should be declared
-- `DEFERRABLE INITIALLY IMMEDIATE` at creation, or the import will fail to defer
-- it. (Tracked as a convention; a CI lint is a possible follow-up.)
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT cl.relname AS table_name, con.conname AS constraint_name
        FROM pg_constraint con
        JOIN pg_class cl ON cl.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = cl.relnamespace
        WHERE con.contype = 'f'
          AND n.nspname = 'public'
          AND NOT con.condeferrable
    LOOP
        EXECUTE format(
            'ALTER TABLE public.%I ALTER CONSTRAINT %I DEFERRABLE INITIALLY IMMEDIATE',
            r.table_name,
            r.constraint_name
        );
    END LOOP;
END $$;
