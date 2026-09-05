//! PMS-683: durable guard for the tenant-isolation RLS invariant.
//!
//! Every `public` table with a `tenant_id` column must have Row-Level Security
//! ENABLED and FORCED plus a `tenant_isolation` policy (the fail-closed backstop
//! introduced by `038_rls_fail_closed.sql`). This test queries the fully-migrated
//! schema that `#[sqlx::test]` builds and fails if any tenant-scoped table is
//! missing that coverage, so a newly added tenant table cannot silently skip RLS
//! the way the PMS-683 thirteen did.
//!
//! `ALLOWED_WITHOUT_RLS` is the set of tenant tables read on the raw NOBYPASSRLS
//! `mokosh_app` pool without setting the `app.current_tenant` GUC (see
//! `094_rls_quotes_backstop.sql`). Enabling RLS on one of them fail-closes that
//! read to zero rows, so each entry states why its read cannot carry a tenant
//! GUC. Historically the list also held tables merely WAITING for their service
//! to move to `begin_with_tenant`; those were all migrated and the list emptied
//! (migration 095). PMS-1040 reopened it for the opposite case: a read that is
//! cross-tenant by construction and must stay exempt permanently. When a table
//! does gain RLS, delete it from this list; the assertions below keep the list
//! honest in both directions.
//!
//! PMS-874 adds the other half of the universe. A table with NO `tenant_id`
//! column was outside this file's sweep entirely, so a child table isolated only
//! through a parent FK could skip RLS in silence - which is exactly what
//! `quote_lines` (092) and `credit_note_lines` (122) both did, after `041` had
//! already hand-covered five tables in that same shape. The second test below
//! sweeps every tenantless table and requires the `tenant_isolation` policy on
//! all of them, with `TENANTLESS_WITHOUT_RLS` as the documented exemption list.
//!
//! This guard is pure schema introspection (no role creation), so it runs under
//! any migrated database, including the local `just test-integration` migrator
//! role - unlike the RLS-behaviour tests, which need a superuser to create the
//! unprivileged probe role.

use sqlx::PgPool;

/// Tenant-scoped tables intentionally NOT under RLS, because the read that
/// reaches them cannot carry an `app.current_tenant` GUC. Keep sorted.
///
/// PMS-683 (tail) emptied this list: the 11 tables previously deferred here had
/// their services migrated onto `begin_with_tenant` and gained the fail-closed
/// `tenant_isolation` policy in migration 095. PMS-1040 reopened it with exactly
/// one entry, for a table that must NEVER gain the policy rather than one
/// waiting for its service to move.
///
/// * `tenant_membership_entitlements` - the pre-auth, cross-tenant entitlement
///   lookup. `AuthService::ensure_principal_usable`
///   (`src/modules/auth/service.rs`, the read carrying the
///   `SAFETY (PMS-285 / PMS-692)` note) reads it on the bare NOBYPASSRLS
///   `.pool()` with no `app.current_tenant` GUC, because the caller is not yet
///   authenticated into a tenant. RLS would fail-close that read to `None`, and
///   a missing entitlement row means "fresh instance, never lock anybody out",
///   so the gate would silently pass every tenant including suspended ones.
///   Decided in migration `154_tenant_membership_entitlements.sql`'s header
///   (MAPPS-459 / PMS-728) and restated at the call site; PMS-1040 moved it here
///   because a rule recorded only in prose is not a rule.
const ALLOWED_WITHOUT_RLS: &[&str] = &["tenant_membership_entitlements"];

/// Tables with NO `tenant_id` column that legitimately carry no
/// `tenant_isolation` policy. Keep sorted; every entry states its reason.
///
/// * `_sqlx_migrations` - sqlx's own ledger. Global schema state, written only
///   by the BYPASSRLS migrator role, holding no tenant data.
/// * `identities` - the cross-tenant identity plane (MAPPS-475, migration
///   `157_identities_and_memberships.sql`). One human is one row that exists
///   across every tenant they hold a seat in, so there is no tenant to scope to
///   and no parent to join through; login-by-email resolves it before any GUC
///   can be set. Every reader takes the BYPASSRLS migrator pool
///   (`IdentityRepo::*` call sites in `src/modules/auth/middleware.rs`,
///   `src/modules/auth/service.rs`, `src/modules/tenants/routes.rs`). Its seat
///   table, `tenant_memberships`, DOES carry a `tenant_id` and gained the policy
///   in migration 191. PMS-1040.
/// * `platform_admins` - the platform super-admin registry (MAPPS-513,
///   migration `160_platform_admins.sql`), deliberately outside tenancy so the
///   persona's credential lifecycle never intersects a tenant admin's identity.
///   Read on the pre-auth login path; every `PlatformAdminRepo::*` call site in
///   `src/modules/platform/service.rs` uses the migrator pool. PMS-1040.
/// * `tenants` - the isolation root. It is the table every policy's `tenant_id`
///   points at, so it cannot itself be scoped by one; `TenantService` reaches it
///   on the migrator pool behind a `super_admin` route.
///
/// Anything else in this shape is a child table isolated through a parent
/// foreign key, and gets the fail-closed parent-join policy (migrations `041`
/// and `128`). PMS-874.
const TENANTLESS_WITHOUT_RLS: &[&str] = &[
    "_sqlx_migrations",
    "identities",
    "platform_admins",
    "tenants",
];

/// `public` tables missing full fail-closed RLS (enabled AND forced AND a
/// `tenant_isolation` policy), restricted to the half of the schema that does
/// (`true`) or does not (`false`) carry a `tenant_id` column. The two halves
/// together are every table, which is the point: the `tenant_id` predicate is
/// what let `quote_lines` and `credit_note_lines` sit outside the sweep.
async fn uncovered_tables(pool: &PgPool, with_tenant_id: bool) -> Vec<String> {
    sqlx::query_scalar(
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
           ) = $1
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
    .bind(with_tenant_id)
    .fetch_all(pool)
    .await
    .expect("query tables lacking fail-closed RLS")
}

/// Assert the exemption list in BOTH directions: nothing uncovered outside it,
/// and no entry in it that has since gained a policy. A one-directional check
/// lets the list keep naming tables that are already fixed, which is how it
/// stops being read as the statement of what is genuinely exempt.
fn assert_exemptions_honest(uncovered: &[String], exempt: &[&str], list_name: &str, remedy: &str) {
    let unexpected: Vec<&str> = uncovered
        .iter()
        .map(String::as_str)
        .filter(|t| !exempt.contains(t))
        .collect();
    assert!(
        unexpected.is_empty(),
        "tables missing the fail-closed `tenant_isolation` RLS backstop: \
         {unexpected:?}. Enable + force RLS and create the policy in a new \
         migration ({remedy}), or add the table to {list_name} with its reason."
    );

    let stale: Vec<&str> = exempt
        .iter()
        .copied()
        .filter(|t| !uncovered.iter().any(|u| u == t))
        .collect();
    assert!(
        stale.is_empty(),
        "these tables now have RLS and must be removed from {list_name}: {stale:?}"
    );
}

#[sqlx::test]
async fn every_tenant_table_has_rls_or_is_allowlisted(pool: PgPool) {
    // Tables that have a `tenant_id` column but are missing full fail-closed RLS.
    // `tenants` itself has no `tenant_id` column and is excluded by the predicate;
    // it is covered by the tenantless sweep below.
    let uncovered = uncovered_tables(&pool, true).await;
    assert_exemptions_honest(
        &uncovered,
        ALLOWED_WITHOUT_RLS,
        "ALLOWED_WITHOUT_RLS",
        "mirror 038_rls_fail_closed.sql / 090 / 091",
    );
}

/// PMS-874: the other half of the universe. A table with no `tenant_id` column
/// is isolated only through its parent foreign key, and nothing swept for it:
/// `041` hand-listed five such tables, then `quote_lines` (092) and
/// `credit_note_lines` (122) were added in the same shape with no policy at all
/// and no test went red. This one does.
#[sqlx::test]
async fn every_tenantless_table_has_rls_or_is_exempt(pool: PgPool) {
    let uncovered = uncovered_tables(&pool, false).await;
    assert_exemptions_honest(
        &uncovered,
        TENANTLESS_WITHOUT_RLS,
        "TENANTLESS_WITHOUT_RLS",
        "mirror the parent-join block in 041_rls_cover_tenantless_tables.sql / 128",
    );
}
