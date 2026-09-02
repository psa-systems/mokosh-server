-- PMS-875: move the system-shared READ half into the opt-in function.
--
-- `039_system_shared_class.sql` split the class in two: a one-shot loop that
-- recreated `tenant_isolation` with the `tenant_id IS NULL` read disjunct on
-- every table that had a `tenant_id` column ON THE DAY 039 RAN, and an opt-in
-- helper (`mokosh_enable_system_shared`) that only dropped the NOT NULL and
-- attached the write guard. Every tenant table created since (094, 095, 105 and
-- every new-table migration, which copies the plain 038 block) carries the
-- non-disjunct policy, so opting one of them in stored global rows that no
-- tenant could read: `tenant_id IS NULL` never satisfies `tenant_id = <uuid>`.
-- Silent, not loud - the rows are simply invisible forever.
--
-- The fix is to make the opt-in own the read half too, so it no longer depends
-- on when the table was created. 039 is immutable and is NOT edited; this
-- CREATE OR REPLACE supersedes its definition of the function.
--
-- WITH CHECK deliberately does NOT gain the disjunct, exactly as in 039: a
-- global row is written only through the privileged path guarded by
-- `mokosh_guard_system_shared_row`, and a `tenant_id IS NULL` disjunct in
-- WITH CHECK would let an ordinary session create one.
CREATE OR REPLACE FUNCTION mokosh_enable_system_shared(target regclass)
RETURNS void AS $$
BEGIN
    -- Fail before touching anything. The parent-join tables covered by 041 have
    -- no `tenant_id` column and cannot join this class; dropping their policy
    -- first and failing on the ALTER afterwards would leave them exposed.
    IF NOT EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = target
          AND attname = 'tenant_id'
          AND attnum > 0
          AND NOT attisdropped
    ) THEN
        RAISE EXCEPTION
            'table % has no tenant_id column, so it cannot join the system-shared class', target
            USING ERRCODE = 'undefined_column';
    END IF;

    EXECUTE format('ALTER TABLE %s ALTER COLUMN tenant_id DROP NOT NULL', target);

    -- READ: recreate the policy in the 039 disjunct form. Same expression as
    -- 039's loop body, so a table opted in here is indistinguishable from one
    -- the loop covered.
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %s', target);
    EXECUTE format($pol$
        CREATE POLICY tenant_isolation ON %s
        USING (
            tenant_id IS NULL
            OR tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::UUID
        )
        WITH CHECK (
            tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::UUID
        )
    $pol$, target);

    -- WRITE: the 039 backstop, unchanged.
    EXECUTE format('DROP TRIGGER IF EXISTS guard_system_shared_row ON %s', target);
    EXECUTE format($trg$
        CREATE TRIGGER guard_system_shared_row
        BEFORE INSERT OR UPDATE OR DELETE ON %s
        FOR EACH ROW EXECUTE FUNCTION mokosh_guard_system_shared_row()
    $trg$, target);
END;
$$ LANGUAGE plpgsql;
