//! PMS-875 regression: opting a table into the system-shared class produces
//! globally READABLE rows, whatever migration created the table.
//!
//! `039_system_shared_class.sql` reserved the class in two halves: a one-shot
//! loop that added the `tenant_id IS NULL` read disjunct to `tenant_isolation`
//! on the tables that existed then, and `mokosh_enable_system_shared`, which
//! dropped the NOT NULL and attached the write guard but never touched the
//! policy. Every table created after `039` (094, 095, 105, ...) carries the
//! plain `038` policy, so opting one in stored global rows that no tenant could
//! ever read - a silent failure, not a loud one. `127` moved the read half into
//! the function; these tests prove it on `saved_dashboards`, created by `064`
//! and given its policy by `095`, long after `039` ran.
//!
//! Like `rls_isolation.rs`, the policy assertions run under a dedicated
//! `NOSUPERUSER NOBYPASSRLS` role, because `#[sqlx::test]` connects as the
//! superuser, which bypasses RLS unconditionally. Each `#[sqlx::test]` gets its
//! own database, so the opt-in's schema change does not leak into other tests.

use sqlx::PgPool;
use uuid::Uuid;

/// Seed a tenant and a user in it, returning both ids. Runs as the superuser,
/// so RLS does not interfere with setup.
async fn seed_tenant_with_user(conn: &mut sqlx::PgConnection, name: &str) -> (Uuid, Uuid) {
    let tenant_id = Uuid::new_v4();
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

/// The `USING` expression of a table's `tenant_isolation` policy.
async fn tenant_isolation_qual(conn: &mut sqlx::PgConnection, table: &str) -> String {
    sqlx::query_scalar(
        "SELECT qual FROM pg_policies \
         WHERE schemaname = 'public' AND tablename = $1 AND policyname = 'tenant_isolation'",
    )
    .bind(table)
    .fetch_one(&mut *conn)
    .await
    .expect("read tenant_isolation policy expression")
}

#[sqlx::test]
async fn opting_in_a_post_039_table_makes_global_rows_readable(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire dedicated connection");

    let (tenant_a, user_a) = seed_tenant_with_user(&mut conn, "sysshared-tenant-a").await;
    let (tenant_b, _user_b) = seed_tenant_with_user(&mut conn, "sysshared-tenant-b").await;

    // Precondition: `095` gave this table the plain `038` policy, with no
    // `IS NULL` disjunct. This is the state that made the opt-in silent.
    let before = tenant_isolation_qual(&mut conn, "saved_dashboards").await;
    assert!(
        !before.contains("IS NULL"),
        "saved_dashboards is only a meaningful subject while its policy lacks the disjunct, got: {before}"
    );

    sqlx::query("SELECT mokosh_enable_system_shared('saved_dashboards')")
        .execute(&mut *conn)
        .await
        .expect("opt saved_dashboards into the system-shared class");

    // The opt-in now owns the read half.
    let after = tenant_isolation_qual(&mut conn, "saved_dashboards").await;
    assert!(
        after.contains("IS NULL"),
        "the opt-in must add the tenant_id IS NULL read disjunct, got: {after}"
    );
    // WITH CHECK must NOT gain it: a global row is writable only through the
    // privileged path, never by an ordinary session.
    let with_check: String = sqlx::query_scalar(
        "SELECT with_check FROM pg_policies \
         WHERE schemaname = 'public' AND tablename = 'saved_dashboards' \
         AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("read tenant_isolation WITH CHECK");
    assert!(
        !with_check.contains("IS NULL"),
        "WITH CHECK must stay non-disjunct or an ordinary session could write a global row, got: {with_check}"
    );

    // A global row, written from a privileged session (superuser bypasses RLS;
    // the write guard still demands the explicit GUC).
    let global_id = Uuid::new_v4();
    sqlx::query("SELECT set_config('app.allow_system_writes', 'on', false)")
        .execute(&mut *conn)
        .await
        .expect("arm system writes");
    sqlx::query(
        "INSERT INTO saved_dashboards (id, tenant_id, user_id, name) \
         VALUES ($1, NULL, $2, 'system dashboard')",
    )
    .bind(global_id)
    .bind(user_a)
    .execute(&mut *conn)
    .await
    .expect("insert the global row");

    // A per-tenant row under tenant A, to prove the disjunct widened the read to
    // global rows ONLY and left tenant isolation intact.
    sqlx::query(
        "INSERT INTO saved_dashboards (id, tenant_id, user_id, name) \
         VALUES ($1, $2, $3, 'tenant A dashboard')",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_a)
    .bind(user_a)
    .execute(&mut *conn)
    .await
    .expect("insert tenant A's own row");

    sqlx::query("SELECT set_config('app.allow_system_writes', 'off', false)")
        .execute(&mut *conn)
        .await
        .expect("disarm system writes");

    // Unprivileged role, under an UNRELATED tenant's GUC.
    let role = format!("mokosh_pms875_test_{}", Uuid::new_v4().simple());
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
    sqlx::query(&format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON saved_dashboards TO {role}"
    ))
    .execute(&mut *conn)
    .await
    .expect("grant table");
    sqlx::query(&format!("SET ROLE {role}"))
        .execute(&mut *conn)
        .await
        .expect("set role");
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(tenant_b.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to the unrelated tenant");

    // READ: the global row is visible under a tenant that has nothing to do with
    // it. Before `127` this count was 0 and nothing said so.
    let visible_global: i64 =
        sqlx::query_scalar("SELECT count(*) FROM saved_dashboards WHERE id = $1")
            .bind(global_id)
            .fetch_one(&mut *conn)
            .await
            .expect("count the global row under tenant B");
    assert_eq!(
        visible_global, 1,
        "a system-shared row must be readable by every tenant"
    );

    // ...and tenant A's own row still is not.
    let visible_foreign: i64 =
        sqlx::query_scalar("SELECT count(*) FROM saved_dashboards WHERE tenant_id = $1")
            .bind(tenant_a)
            .fetch_one(&mut *conn)
            .await
            .expect("count tenant A's row under tenant B");
    assert_eq!(
        visible_foreign, 0,
        "the disjunct must widen the read to global rows only, not across tenants"
    );

    // WRITE: an ordinary session can neither create, change, nor remove a global
    // row. INSERT is refused by the non-disjunct WITH CHECK and by the guard
    // trigger; UPDATE and DELETE reach the row through the widened USING clause
    // and are refused by the trigger, which is exactly why it exists.
    let err = sqlx::query(
        "INSERT INTO saved_dashboards (id, tenant_id, user_id, name) \
         VALUES ($1, NULL, $2, 'forged global')",
    )
    .bind(Uuid::new_v4())
    .bind(user_a)
    .execute(&mut *conn)
    .await
    .expect_err("an ordinary session must not create a global row");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "expected insufficient_privilege (42501) on INSERT, got: {err}"
    );

    let err = sqlx::query("UPDATE saved_dashboards SET name = 'hijacked' WHERE id = $1")
        .bind(global_id)
        .execute(&mut *conn)
        .await
        .expect_err("an ordinary session must not change a global row");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "expected insufficient_privilege (42501) on UPDATE, got: {err}"
    );

    let err = sqlx::query("DELETE FROM saved_dashboards WHERE id = $1")
        .bind(global_id)
        .execute(&mut *conn)
        .await
        .expect_err("an ordinary session must not delete a global row");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "expected insufficient_privilege (42501) on DELETE, got: {err}"
    );

    // Cleanup: roles are cluster-global while the database is per-test.
    sqlx::query("RESET ROLE")
        .execute(&mut *conn)
        .await
        .expect("reset role");
    sqlx::query(&format!("REVOKE ALL ON saved_dashboards FROM {role}"))
        .execute(&mut *conn)
        .await
        .expect("revoke table");
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
async fn opting_in_a_tenantless_table_raises_and_leaves_its_policy_alone(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire dedicated connection");

    // `kb_article_versions` is one of the `041` parent-join tables: no
    // `tenant_id` column, so it cannot join the class. The function must say so
    // instead of dropping the policy that isolates it.
    let err = sqlx::query("SELECT mokosh_enable_system_shared('kb_article_versions')")
        .execute(&mut *conn)
        .await
        .expect_err("a table with no tenant_id column must be refused");
    let db_err = err.as_database_error().expect("a database error");
    assert_eq!(
        db_err.code().as_deref(),
        Some("42703"),
        "expected undefined_column (42703), got: {err}"
    );
    assert!(
        db_err.message().contains("system-shared class"),
        "the refusal must name the class it is refusing, got: {}",
        db_err.message()
    );

    let qual = tenant_isolation_qual(&mut conn, "kb_article_versions").await;
    assert!(
        qual.contains("kb_articles"),
        "the parent-join policy must survive the refusal, got: {qual}"
    );
}
