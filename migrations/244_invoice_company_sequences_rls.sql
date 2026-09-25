-- PMS-999 (fixing PMS-979): the per-customer invoice counter had no RLS.
--
-- Migration 243 created `invoice_company_sequences` and granted it to
-- `mokosh_app` (PMS-1265) but did not attach the fail-closed
-- `tenant_isolation` policy every tenant-scoped table carries. The 024/038
-- policy loops had already run, so a table created afterwards does not
-- inherit one; it has to be attached explicitly, which is the PMS-257
-- posture. `tests/rls_coverage.rs` is what caught it, and it is the reason
-- that test exists: the table is written on the request-serving pool, which
-- is NOBYPASSRLS, so without a policy the only thing keeping one tenant's
-- counter away from another's was the `WHERE tenant_id = $1` in the query.
--
-- The window was small - migration 243 has not been deployed anywhere yet -
-- and the consequence would not have been a leak of anything a customer
-- reads. It would have been worse in a quieter way: a missing WHERE clause
-- in some future query against this table would have silently drawn another
-- tenant's next invoice number instead of failing closed.
ALTER TABLE invoice_company_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_company_sequences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoice_company_sequences
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
