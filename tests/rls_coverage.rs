//! PMS-683: durable guard for the tenant-isolation RLS invariant.
//!
//! Every `public` table with a `tenant_id` column must have Row-Level Security
//! ENABLED and FORCED plus a `tenant_isolation` policy (the fail-closed backstop
//! introduced by `038_rls_fail_closed.sql`). This test queries the fully-migrated
//! schema that `#[sqlx::test]` builds and fails if any tenant-scoped table is
//! missing that coverage, so a newly added tenant table cannot silently skip RLS
//! the way the PMS-683 thirteen did.
//!
//! `ALLOWED_WITHOUT_RLS` is the set of tenant tables whose feature services still
//! query the raw NOBYPASSRLS `mokosh_app` pool without setting the
//! `app.current_tenant` GUC (see `094_rls_quotes_backstop.sql`). Enabling RLS on
//! them before those services move to `begin_with_tenant` would fail-close their
//! reads, so they are deferred to the `begin_with_tenant` read-path migration
//! (PMS-256 / PMS-285 lineage). When a service is migrated and its table gains
//! RLS, delete it from this list; the assertions below keep the list honest in
//! both directions. The invariant is fully restored once the list is empty.
//!
//! This guard is pure schema introspection (no role creation), so it runs under
//! any migrated database, including the local `just test-integration` migrator
//! role - unlike the RLS-behaviour tests, which need a superuser to create the
//! unprivileged probe role.

use sqlx::PgPool;

/// Tenant-scoped tables intentionally NOT yet under RLS, pending their services'
/// migration to `begin_with_tenant`. Keep sorted.
///
/// PMS-683 (tail): now EMPTY. The 11 tables previously deferred here had their
/// services migrated onto `begin_with_tenant` and gained the fail-closed
/// `tenant_isolation` policy in migration 095, so the invariant is fully
/// restored: every tenant-scoped `public` table has RLS enabled, forced, and a
/// `tenant_isolation` policy. A newly added tenant table that skips RLS will now
/// fail this test outright rather than being silently allowlisted.
const ALLOWED_WITHOUT_RLS: &[&str] = &[];

#[sqlx::test]
async fn every_tenant_table_has_rls_or_is_allowlisted(pool: PgPool) {
    // Tables that have a `tenant_id` column but are missing full fail-closed RLS
    // (RLS enabled AND forced AND a `tenant_isolation` policy). `tenants` itself
    // has no `tenant_id` column and is excluded by the column predicate.
    let uncovered: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT c.relname
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relkind = 'r'
           AND EXISTS (
               SELECT 1
                 FROM information_schema.columns col
                WHERE col.table_schema = 'public'
                  AND col.table_name = c.relname
                  AND col.column_name = 'tenant_id'
           )
           AND NOT (
               c.relrowsecurity
               AND c.relforcerowsecurity
               AND EXISTS (
                   SELECT 1
                     FROM pg_policy p
                    WHERE p.polrelid = c.oid
                      AND p.polname = 'tenant_isolation'
               )
           )
         ORDER BY c.relname
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("query tenant_id tables lacking fail-closed RLS");

    // 1) No tenant table may lack RLS unless it is explicitly allowlisted. A new
    //    tenant_id table must enable RLS in its migration (mirror
    //    038_rls_fail_closed.sql / 090 / 091) or, if its service is not yet
    //    GUC-safe, be added to ALLOWED_WITHOUT_RLS with a tracking note.
    let unexpected: Vec<&str> = uncovered
        .iter()
        .map(String::as_str)
        .filter(|t| !ALLOWED_WITHOUT_RLS.contains(t))
        .collect();
    assert!(
        unexpected.is_empty(),
        "tenant-scoped tables missing the fail-closed `tenant_isolation` RLS \
         backstop (enable + force RLS and create the policy in a new migration): \
         {unexpected:?}"
    );

    // 2) Keep the allowlist honest: an allowlisted table that now HAS RLS must be
    //    removed from ALLOWED_WITHOUT_RLS so the list shrinks to empty as the
    //    begin_with_tenant migration completes.
    let stale: Vec<&str> = ALLOWED_WITHOUT_RLS
        .iter()
        .copied()
        .filter(|t| !uncovered.iter().any(|u| u == t))
        .collect();
    assert!(
        stale.is_empty(),
        "these tables now have RLS and must be removed from ALLOWED_WITHOUT_RLS: \
         {stale:?}"
    );
}
