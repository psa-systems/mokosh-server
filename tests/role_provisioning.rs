//! PMS-1153: the provisioner's fast path asks the database which roles exist
//! instead of inferring it from one successful connection.
//!
//! The decision itself is unit-tested in `src/db/provision.rs`. What only a real
//! Postgres can show is the probe and the creation step: that `pg_roles` is read
//! the way the decision assumes, that the connected role is reported
//! truthfully, and that creating a missing role is idempotent - two replicas
//! booting at once may both decide to create it, and the loser must not fail.
//!
//! The role cluster is shared by every test database, so these cases never
//! touch `mokosh_app` (other suites depend on it). They probe a role name
//! nothing else uses and drop it afterwards.

use mokosh_server::db::provision::{create_nologin_roles, probe_roles};
use sqlx::PgPool;
use uuid::Uuid;

/// A role name nothing else in the cluster uses, so creating and dropping it
/// cannot disturb a parallel test.
fn throwaway_role() -> String {
    format!("pms1153_{}", Uuid::new_v4().simple())
}

async fn drop_role(pool: &PgPool, role: &str) {
    sqlx::query(&format!("DROP ROLE IF EXISTS \"{role}\""))
        .execute(pool)
        .await
        .expect("drop the throwaway role");
}

/// The probe reports the role that connected and whether it may create roles.
/// `#[sqlx::test]` connects as the cluster superuser, which is exactly the
/// shape of staging's single role.
#[sqlx::test]
async fn the_probe_reports_who_connected_and_whether_it_may_create_roles(pool: PgPool) {
    let probe = probe_roles(&pool, &[]).await.expect("probe");
    let current: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .expect("current_user");
    assert_eq!(
        probe.connected_as, current,
        "the log names the role that actually connected, not an assumed one"
    );
    assert!(
        probe.can_create_roles,
        "the test superuser can create roles"
    );
    assert!(probe.missing.is_empty(), "nothing was asked for");
}

/// A role that does not exist is reported missing; one that does is not.
#[sqlx::test]
async fn the_probe_finds_a_missing_role_and_ignores_a_present_one(pool: PgPool) {
    let absent = throwaway_role();
    let current: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .expect("current_user");

    let probe = probe_roles(&pool, &[absent.as_str(), current.as_str()])
        .await
        .expect("probe");
    assert_eq!(
        probe.missing,
        vec![absent.clone()],
        "only the absent one is missing"
    );
}

/// The creation step makes the role, makes it NOLOGIN, and a second run is a
/// no-op rather than an error - the two-replicas-at-boot case.
#[sqlx::test]
async fn a_missing_role_is_created_nologin_and_creating_it_twice_is_harmless(pool: PgPool) {
    let role = throwaway_role();

    create_nologin_roles(&pool, std::slice::from_ref(&role))
        .await
        .expect("first create");
    create_nologin_roles(&pool, std::slice::from_ref(&role))
        .await
        .expect("a second create is a no-op, not an error");

    let can_login: bool = sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname = $1")
        .bind(&role)
        .fetch_one(&pool)
        .await
        .expect("the role exists");
    assert!(
        !can_login,
        "a role an automatic step created must not be able to log in"
    );

    let probe = probe_roles(&pool, &[role.as_str()]).await.expect("probe");
    assert!(probe.missing.is_empty(), "and the probe now finds it");

    drop_role(&pool, &role).await;
}

/// The point of the whole change: once the role exists, a GRANT to it - the
/// statement migrations 207 and 210 end with - succeeds. Before PMS-1153 the
/// fast path could skip on a database where this failed.
#[sqlx::test]
async fn a_grant_to_the_created_role_succeeds(pool: PgPool) {
    let role = throwaway_role();
    create_nologin_roles(&pool, std::slice::from_ref(&role))
        .await
        .expect("create");

    sqlx::query("CREATE TABLE pms1153_probe (id INT)")
        .execute(&pool)
        .await
        .expect("a table to grant on");
    sqlx::query(&format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON pms1153_probe TO \"{role}\""
    ))
    .execute(&pool)
    .await
    .expect("the GRANT a migration makes now succeeds");

    // The grant holds a dependency on the role; revoke before dropping it.
    sqlx::query(&format!("REVOKE ALL ON pms1153_probe FROM \"{role}\""))
        .execute(&pool)
        .await
        .expect("revoke");
    drop_role(&pool, &role).await;
}
