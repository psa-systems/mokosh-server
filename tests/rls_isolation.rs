//! PMS-257 regression: the `tenant_isolation` RLS policy is fail-closed and
//! enforces `WITH CHECK` on writes.
//!
//! Migration `038_rls_fail_closed.sql` rewrites the policy so that an unset
//! `app.current_tenant` GUC matches NO rows (fail-closed read) and a write whose
//! `tenant_id` does not equal the GUC is rejected (WITH CHECK), with
//! `FORCE ROW LEVEL SECURITY` so even the table owner is constrained.
//!
//! `#[sqlx::test]` connects as the cluster superuser, which bypasses RLS
//! unconditionally (FORCE does not apply to superusers or BYPASSRLS roles). To
//! observe the policy this test creates an unprivileged application-style role
//! (`NOSUPERUSER NOBYPASSRLS` - the posture the production application
//! connection must use) and `SET ROLE`s to it on a dedicated connection. The
//! migration / owner role keeps its bypass, exactly as the deployment split
//! requires.

use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn rls_fail_closed_and_with_check(pool: PgPool) {
    // The default tenant the seed migration always inserts.
    let tenant_a = Uuid::from_u128(1);
    // An arbitrary other tenant id - only ever used as a GUC value, so it does
    // not need a matching `tenants` row.
    let wrong_tenant = Uuid::new_v4();
    // Roles are cluster-global while each #[sqlx::test] gets its own database,
    // so use a unique, valid-identifier role name to avoid cross-test clashes.
    let role = format!("mokosh_rls_test_{}", Uuid::new_v4().simple());

    // A single dedicated connection so SET ROLE and the session GUC persist
    // across the statements below.
    let mut conn = pool.acquire().await.expect("acquire dedicated connection");

    // Seed one company under tenant A as the superuser (bypasses RLS), so there
    // is a row the unprivileged role should and should not be able to see.
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'RLS probe')")
        .bind(Uuid::new_v4())
        .bind(tenant_a)
        .execute(&mut *conn)
        .await
        .expect("seed company under tenant A");

    // How many companies tenant A legitimately owns. Beyond the probe above,
    // seed migrations may create a per-tenant internal "own company" (PMS-413
    // migration 062), so capture the owner-visible count here rather than
    // hard-coding 1 - all of these rows belong to tenant A and must be visible
    // under the matching GUC.
    let tenant_a_companies: i64 =
        sqlx::query_scalar("SELECT count(*) FROM companies WHERE tenant_id = $1")
            .bind(tenant_a)
            .fetch_one(&mut *conn)
            .await
            .expect("count tenant A companies as owner");

    // Create the unprivileged application role and grant it table access.
    sqlx::query(&format!(
        "CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS"
    ))
    .execute(&mut *conn)
    .await
    .expect("create unprivileged app role");
    sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {role}"))
        .execute(&mut *conn)
        .await
        .expect("grant schema usage");
    sqlx::query(&format!("GRANT SELECT, INSERT ON companies TO {role}"))
        .execute(&mut *conn)
        .await
        .expect("grant table privileges");

    // The application role must NOT be able to bypass RLS.
    let bypass: bool = sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = $1")
        .bind(&role)
        .fetch_one(&mut *conn)
        .await
        .expect("read rolbypassrls");
    assert!(!bypass, "application role must lack BYPASSRLS");

    // Become the unprivileged role for the policy assertions.
    sqlx::query(&format!("SET ROLE {role}"))
        .execute(&mut *conn)
        .await
        .expect("set role to unprivileged app role");

    // 1) Fail-closed read: no GUC set on this fresh session => zero rows.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM companies")
        .fetch_one(&mut *conn)
        .await
        .expect("count with no GUC");
    assert_eq!(count, 0, "an unset GUC must expose zero rows (fail-closed)");

    // 2) With the matching GUC the row becomes visible (the policy is not a
    //    blanket deny). RLS filters purely by tenant_id, not company_type, so
    //    the matching GUC exposes every tenant-A row - including the internal
    //    own-company (PMS-413 migration 062). Count without a company_type
    //    filter so this read mirrors the owner-visible count captured above; an
    //    asymmetric `<> 'internal'` predicate here would undercount and fail
    //    even though RLS is behaving correctly.
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(tenant_a.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to tenant A");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM companies")
        .fetch_one(&mut *conn)
        .await
        .expect("count with tenant A GUC");
    assert_eq!(
        count, tenant_a_companies,
        "the matching GUC must expose exactly tenant A's rows"
    );

    // 3) WITH CHECK: a write whose tenant_id != the GUC is rejected.
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(wrong_tenant.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to the wrong tenant");
    let err = sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'cross')")
        .bind(Uuid::new_v4())
        .bind(tenant_a)
        .execute(&mut *conn)
        .await
        .expect_err("a write with the wrong GUC must be rejected by WITH CHECK");
    // 42501 = insufficient_privilege, the SQLSTATE Postgres raises on an RLS
    // WITH CHECK violation.
    let code = err.as_database_error().and_then(|e| e.code());
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "expected an RLS WITH CHECK violation (42501), got: {err}"
    );

    // 4) A write whose tenant_id matches the GUC passes WITH CHECK.
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(tenant_a.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC back to tenant A");
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'same')")
        .bind(Uuid::new_v4())
        .bind(tenant_a)
        .execute(&mut *conn)
        .await
        .expect("a matching-tenant write must pass WITH CHECK");

    // Cleanup: shed privileges and drop the cluster-global role.
    sqlx::query("RESET ROLE")
        .execute(&mut *conn)
        .await
        .expect("reset role");
    sqlx::query(&format!("REVOKE ALL ON companies FROM {role}"))
        .execute(&mut *conn)
        .await
        .expect("revoke table privileges");
    sqlx::query(&format!("REVOKE ALL ON SCHEMA public FROM {role}"))
        .execute(&mut *conn)
        .await
        .expect("revoke schema usage");
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&mut *conn)
        .await
        .expect("drop app role");
}
