//! PMS-258 regression: the five tables the dynamic RLS loop skipped (because
//! they carry no `tenant_id` column, or carried a global unique key) are now
//! covered by fail-closed row level security.
//!
//! Two properties are proven:
//!   1. `user_oauth_identities` no longer collides across tenants: the same
//!      `(provider, subject)` can exist once PER tenant, and a same-tenant
//!      duplicate is rejected. This is the critical cross-tenant identity fix.
//!   2. The parent-join policy on a child table (`kb_article_versions`) is
//!      fail-closed: with no `app.current_tenant` GUC an unprivileged
//!      (`NOSUPERUSER NOBYPASSRLS`) role sees zero rows, with the parent's
//!      tenant set it sees exactly that tenant's rows, and a write whose parent
//!      lives in another tenant is rejected by WITH CHECK.
//!
//! PMS-874 adds the third: `quote_lines` was created by `092_quotes_entity.sql`
//! in that same parent-FK shape, after `041` had hand-listed its five tables,
//! and carried no policy at all until `128_rls_tenantless_child_tables.sql`. It
//! is proven fail-closed here by the same three properties. The sweep that stops
//! a fourth table slipping through lives in `rls_coverage.rs`; this file proves
//! the policies actually behave, which schema introspection cannot.
//!
//! Like `rls_isolation.rs`, the policy assertions run under a dedicated
//! unprivileged role because `#[sqlx::test]` connects as the superuser, which
//! bypasses RLS unconditionally.

use sqlx::PgPool;
use uuid::Uuid;

/// Seed a tenant, a user in it, and return the ids. Runs as the superuser, so
/// RLS does not interfere with setup.
async fn seed_tenant_with_user(conn: &mut sqlx::PgConnection, name: &str) -> (Uuid, Uuid) {
    let tenant_id = Uuid::new_v4();
    // `name` is unique per call, so it doubles as the required unique slug.
    sqlx::query("INSERT INTO tenants (id, name, slug, kind) VALUES ($1, $2, $2, 'personal')")
        .bind(tenant_id)
        .bind(name)
        .execute(&mut *conn)
        .await
        .expect("seed tenant");

    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status) \
         VALUES ($1, $2, $3, NULL, 'T', 'U', 'super_admin', 'active')",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(format!("{name}@example.test"))
    .execute(&mut *conn)
    .await
    .expect("seed user");

    (tenant_id, user_id)
}

/// Create an unprivileged (`NOSUPERUSER NOBYPASSRLS`) role granted read/write on
/// `tables`, and `SET ROLE` to it. Returns the generated role name for cleanup.
///
/// `#[sqlx::test]` connects as the superuser, which bypasses RLS unconditionally,
/// so a policy assertion made without this switch proves nothing.
async fn set_probe_role(conn: &mut sqlx::PgConnection, tables: &str) -> String {
    let role = format!("mokosh_rls_probe_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS"
    ))
    .execute(&mut *conn)
    .await
    .expect("create app role");
    sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {role}"))
        .execute(&mut *conn)
        .await
        .expect("grant schema");
    sqlx::query(&format!("GRANT SELECT, INSERT ON {tables} TO {role}"))
        .execute(&mut *conn)
        .await
        .expect("grant tables");
    sqlx::query(&format!("SET ROLE {role}"))
        .execute(&mut *conn)
        .await
        .expect("set role");
    role
}

/// Undo [`set_probe_role`]. A role cannot be dropped while it still holds
/// privileges, so the grants come off first.
async fn drop_probe_role(conn: &mut sqlx::PgConnection, role: &str, tables: &str) {
    sqlx::query("RESET ROLE")
        .execute(&mut *conn)
        .await
        .expect("reset role");
    sqlx::query(&format!("REVOKE ALL ON {tables} FROM {role}"))
        .execute(&mut *conn)
        .await
        .expect("revoke tables");
    sqlx::query(&format!("REVOKE ALL ON SCHEMA public FROM {role}"))
        .execute(&mut *conn)
        .await
        .expect("revoke schema");
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&mut *conn)
        .await
        .expect("drop role");
}

#[sqlx::test]
async fn oauth_identity_is_tenant_scoped(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire connection");

    let (tenant_a, user_a) = seed_tenant_with_user(&mut conn, "tenant-a").await;
    let (tenant_b, user_b) = seed_tenant_with_user(&mut conn, "tenant-b").await;

    let shared_subject = "google-subject-shared-across-tenants";

    // The SAME (provider, subject) inserts cleanly under tenant A...
    sqlx::query(
        "INSERT INTO user_oauth_identities (user_id, tenant_id, provider, subject, email) \
         VALUES ($1, $2, 'google', $3, 'a@example.test')",
    )
    .bind(user_a)
    .bind(tenant_a)
    .bind(shared_subject)
    .execute(&mut *conn)
    .await
    .expect("identity under tenant A");

    // ...and ALSO under tenant B. The old global UNIQUE (provider, subject)
    // would have rejected this; the tenant-scoped key must allow it.
    sqlx::query(
        "INSERT INTO user_oauth_identities (user_id, tenant_id, provider, subject, email) \
         VALUES ($1, $2, 'google', $3, 'b@example.test')",
    )
    .bind(user_b)
    .bind(tenant_b)
    .bind(shared_subject)
    .execute(&mut *conn)
    .await
    .expect("same subject must be insertable in a second tenant (no cross-tenant collision)");

    // A duplicate within the SAME tenant is still rejected.
    let err = sqlx::query(
        "INSERT INTO user_oauth_identities (user_id, tenant_id, provider, subject, email) \
         VALUES ($1, $2, 'google', $3, 'dup@example.test')",
    )
    .bind(user_a)
    .bind(tenant_a)
    .bind(shared_subject)
    .execute(&mut *conn)
    .await
    .expect_err("a same-tenant duplicate must violate the unique key");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23505"),
        "expected a unique_violation (23505), got: {err}"
    );
}

#[sqlx::test]
async fn child_table_parent_join_policy_is_fail_closed(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire connection");

    let (tenant_a, user_a) = seed_tenant_with_user(&mut conn, "kb-tenant-a").await;
    let (tenant_b, _user_b) = seed_tenant_with_user(&mut conn, "kb-tenant-b").await;

    // A parent article under tenant A, with one version row (child).
    let article_a = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO kb_articles (id, tenant_id, title, slug, content, status, author_id) \
         VALUES ($1, $2, 'A', 'a-slug', 'body', 'draft', $3)",
    )
    .bind(article_a)
    .bind(tenant_a)
    .bind(user_a)
    .execute(&mut *conn)
    .await
    .expect("seed parent article");
    sqlx::query(
        "INSERT INTO kb_article_versions (article_id, version_number, title, content, edited_by_id) \
         VALUES ($1, 1, 'A v1', 'body', $2)",
    )
    .bind(article_a)
    .bind(user_a)
    .execute(&mut *conn)
    .await
    .expect("seed child version");

    // Unprivileged role to actually observe the policy.
    let tables = "kb_articles, kb_article_versions";
    let role = set_probe_role(&mut conn, tables).await;

    // 1) Fail-closed: no GUC => zero child rows visible.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM kb_article_versions")
        .fetch_one(&mut *conn)
        .await
        .expect("count with no GUC");
    assert_eq!(count, 0, "no GUC must hide the child row (fail-closed)");

    // 2) With tenant A's GUC the child row is visible (parent is in tenant A).
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(tenant_a.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to tenant A");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM kb_article_versions")
        .fetch_one(&mut *conn)
        .await
        .expect("count under tenant A");
    assert_eq!(count, 1, "tenant A's GUC must expose its child row");

    // 3) With tenant B's GUC the same child row is hidden (parent not in B).
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(tenant_b.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to tenant B");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM kb_article_versions")
        .fetch_one(&mut *conn)
        .await
        .expect("count under tenant B");
    assert_eq!(count, 0, "tenant B must not see tenant A's child row");

    // 4) WITH CHECK: inserting a version whose parent lives in tenant A while the
    //    GUC is tenant B is rejected.
    let err = sqlx::query(
        "INSERT INTO kb_article_versions (article_id, version_number, title, content, edited_by_id) \
         VALUES ($1, 2, 'A v2', 'body', $2)",
    )
    .bind(article_a)
    .bind(user_a)
    .execute(&mut *conn)
    .await
    .expect_err("a child write against another tenant's parent must be rejected");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "expected an RLS WITH CHECK violation (42501), got: {err}"
    );

    drop_probe_role(&mut conn, &role, tables).await;
}

/// PMS-874: `quote_lines` carries no `tenant_id` and, until migration `128`, no
/// policy either, so its isolation was entirely the application's job. The
/// service is correct today; this proves the database now refuses the same
/// mistakes on its own.
#[sqlx::test]
async fn quote_lines_parent_join_policy_is_fail_closed(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire connection");

    let (tenant_a, _user_a) = seed_tenant_with_user(&mut conn, "quote-tenant-a").await;
    let (tenant_b, _user_b) = seed_tenant_with_user(&mut conn, "quote-tenant-b").await;

    // A quote under tenant A (quotes.company_id is NOT NULL), with one line.
    let company_a = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme A')")
        .bind(company_a)
        .bind(tenant_a)
        .execute(&mut *conn)
        .await
        .expect("seed company");

    let quote_a = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO quotes (id, tenant_id, company_id, title, status) \
         VALUES ($1, $2, $3, 'Quote A', 'draft')",
    )
    .bind(quote_a)
    .bind(tenant_a)
    .bind(company_a)
    .execute(&mut *conn)
    .await
    .expect("seed parent quote");

    sqlx::query(
        "INSERT INTO quote_lines (quote_id, line_type, description, quantity, unit_price, total) \
         VALUES ($1, 'service', 'Line A', 1, 100.00, 100.00)",
    )
    .bind(quote_a)
    .execute(&mut *conn)
    .await
    .expect("seed child line");

    // The policy's EXISTS reads `quotes`, so the probe role needs both tables.
    let tables = "quotes, quote_lines";
    let role = set_probe_role(&mut conn, tables).await;

    // 1) Fail-closed: no GUC => zero child rows visible.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM quote_lines")
        .fetch_one(&mut *conn)
        .await
        .expect("count with no GUC");
    assert_eq!(count, 0, "no GUC must hide the quote line (fail-closed)");

    // 2) With tenant A's GUC the line is visible (its parent quote is in A).
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(tenant_a.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to tenant A");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM quote_lines")
        .fetch_one(&mut *conn)
        .await
        .expect("count under tenant A");
    assert_eq!(count, 1, "tenant A's GUC must expose its quote line");

    // 3) With tenant B's GUC the same line is hidden (parent not in B).
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(tenant_b.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to tenant B");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM quote_lines")
        .fetch_one(&mut *conn)
        .await
        .expect("count under tenant B");
    assert_eq!(count, 0, "tenant B must not see tenant A's quote line");

    // 4) WITH CHECK: inserting a line onto tenant A's quote while the GUC names
    //    tenant B is rejected. This is the shape the service's tenant-less
    //    `DELETE ... WHERE id = $1 AND quote_id = $2` depended on getting right.
    let err = sqlx::query(
        "INSERT INTO quote_lines (quote_id, line_type, description, quantity, unit_price, total) \
         VALUES ($1, 'service', 'Line B', 1, 50.00, 50.00)",
    )
    .bind(quote_a)
    .execute(&mut *conn)
    .await
    .expect_err("a line written against another tenant's quote must be rejected");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "expected an RLS WITH CHECK violation (42501), got: {err}"
    );

    drop_probe_role(&mut conn, &role, tables).await;
}
