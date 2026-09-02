-- PMS-874: bring the tenantless child tables added after 041 under the same
-- fail-closed row level security every other tenant-reachable table carries.
--
-- The 024/038 policy loops select tables `WHERE column_name = 'tenant_id'`, and
-- 041 (PMS-258) hand-listed the five tables that carry no such column. Anything
-- created afterwards in the parent-FK shape was therefore covered by nothing:
-- 094's scope was explicitly the 13 tables that DO have a `tenant_id`, and
-- `tests/rls_coverage.rs` swept only that same half of the universe, so the gap
-- was silent. Two tables are in it:
--
--   * `quote_lines`      (092_quotes_entity.sql, PMS-671)
--   * `credit_note_lines` (122_credit_notes.sql, PMS-953)
--
-- Both are isolated today only by the application always resolving the parent
-- inside the tenant first: `DELETE FROM quote_lines WHERE id = $1 AND
-- quote_id = $2` carries no tenant predicate of its own. That correct
-- application layer is precisely the thing 038/041 exist not to trust.
--
-- Policy shape mirrors 041's parent-join block exactly, for the reasons stated
-- there: no backfill, and no NOT NULL denormalized column that every INSERT has
-- to keep correct. An unset or empty `app.current_tenant` collapses to NULL, so
-- USING matches no rows (fail-closed read) and WITH CHECK rejects the write;
-- FORCE binds the owner too.
--
-- Enabling RLS on a table ACTIVELY constrains every query the NOBYPASSRLS
-- `mokosh_app` pool makes against it (see 094's scope note), so both tables'
-- access paths were audited first and every one already runs inside a
-- `Database::begin_with_tenant` transaction: the six `quote_lines` statements in
-- `QuotesService` (`recompute_totals`, `get_quote`, `insert_line`,
-- `update_quote`, `update_line`, `delete_line`) and the two `credit_note_lines`
-- statements in `BillingService` (`create_credit_note`, `get_credit_note`).

DO $$
DECLARE
    -- child table, child FK column, parent table
    rec record;
BEGIN
    FOR rec IN
        SELECT * FROM (VALUES
            ('quote_lines',       'quote_id',       'quotes'),
            ('credit_note_lines', 'credit_note_id', 'credit_notes')
        ) AS v(child, fk, parent)
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', rec.child);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', rec.child);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', rec.child);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %1$I
                 USING (
                     EXISTS (
                         SELECT 1 FROM %3$I p
                         WHERE p.id = %1$I.%2$I
                         AND p.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid
                     )
                 )
                 WITH CHECK (
                     EXISTS (
                         SELECT 1 FROM %3$I p
                         WHERE p.id = %1$I.%2$I
                         AND p.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid
                     )
                 )',
            rec.child, rec.fk, rec.parent
        );
    END LOOP;
END $$;
