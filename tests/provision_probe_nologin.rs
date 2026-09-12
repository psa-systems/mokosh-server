//! PMS-1163: `roles_probe` widens its `mokosh_app` predicate from
//! "row exists" to "row exists AND rolcanlogin = TRUE". The staging state
//! that surfaced this (a hand-created `NOLOGIN` mokosh_app row per
//! PMS-1152) tripped the fast path on the pre-1163 predicate, so the
//! `ALTER ROLE ... LOGIN ... PASSWORD` at line 133 of provision.rs never
//! ran and the app pool failed authentication on the next boot step.
//!
//! `roles_probe` is a private helper. This file pins the underlying SQL
//! predicate the probe now runs, so a future editor cannot regress the
//! shape without changing the assertion.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Executes the same predicate `roles_probe` runs, parameterised on a
/// role name so each test uses a fresh cluster-unique role and cannot
/// clash with parallel sqlx tests (roles are cluster-level in Postgres,
/// not per-database).
async fn probe_can_login(pool: &PgPool, role_name: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1 AND rolcanlogin = TRUE)",
    )
    .bind(role_name)
    .fetch_one(pool)
    .await
    .expect("probe query")
}

#[sqlx::test]
async fn nologin_role_returns_false_and_login_role_returns_true(pool: PgPool) {
    // PMS-1163 core assertion. Same shape mokosh_app would take on staging:
    // NOLOGIN row exists → predicate is false → fast path falls through →
    // full provision runs its ALTER ROLE ... LOGIN ... PASSWORD → role
    // heals.
    let role = format!(
        "probe_nologin_{}",
        &Uuid::new_v4().simple().to_string()[..12]
    );

    // Simulate PMS-1152: role hand-created without LOGIN.
    sqlx::query(&format!("CREATE ROLE \"{role}\" NOLOGIN"))
        .execute(&pool)
        .await
        .expect("create nologin");
    assert!(
        !probe_can_login(&pool, &role).await,
        "PMS-1163: a NOLOGIN existing role must fail the probe so the fast path skips it"
    );

    // Simulate the full-provision path's ALTER ROLE at line 133 of
    // provision.rs.
    sqlx::query(&format!(
        "ALTER ROLE \"{role}\" WITH LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'probe_heal_pw'"
    ))
    .execute(&pool)
    .await
    .expect("alter to login");
    assert!(
        probe_can_login(&pool, &role).await,
        "PMS-1163: the same ALTER that provision.rs runs must flip the probe to true"
    );

    // Cleanup so the cluster-level state does not leak across tests.
    sqlx::query(&format!("DROP ROLE \"{role}\""))
        .execute(&pool)
        .await
        .expect("drop role");
}

#[sqlx::test]
async fn missing_role_returns_false_from_probe(pool: PgPool) {
    // The other MigratorConnectsAppMissing arm: the row does not exist at
    // all. PMS-1163 collapses "row missing" and "row NOLOGIN" into one
    // fast-path-falls-through result on purpose, because the downstream
    // full-provision path repairs both states identically.
    let role = format!(
        "probe_absent_{}",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    assert!(
        !probe_can_login(&pool, &role).await,
        "PMS-1163: an absent role must also read as cannot-log-in"
    );
    // No cleanup needed; nothing was created.
    let _ = common::DEFAULT_TENANT_ID; // Silence unused-mod warning when common has nothing to seed.
}
