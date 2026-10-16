//! PMS-1469: healing `mokosh_app`'s password does not re-password the migrator.
//!
//! `roles_probe` can only answer `AppPasswordMismatch` after the migrator
//! credential has already connected, so by the time that arm runs, the one
//! thing known for certain is that the migrator is fine. The statement list it
//! then ran included `ALTER ROLE mokosh_migrator ... PASSWORD
//! <MOKOSH_MIGRATOR_PASSWORD>`, a separately settable production secret that
//! can differ from the password actually embedded in `DATABASE_URL`. That boot
//! SUCCEEDS; the next one cannot connect at all, which turns a one-role
//! incident into a two-role outage with the cause a boot behind.
//!
//! Needs a real Postgres because the claim is about what Postgres still
//! accepts after the statements run, not about which strings we generated
//! (`db::provision::pms_1469_tests` covers the strings). Driven through
//! `provision_statements` against throwaway roles rather than through
//! `provision_roles`, which reads process-global environment that `cargo test`
//! shares across threads, and which would ALTER the cluster-wide real roles.

mod common;

use mokosh_server::db::provision::{
    app_login_with, provision_statements, AppLogin, RoleNames, RolesProbe,
};
use mokosh_test::mokosh_test;
use sqlx::postgres::PgConnectOptions;
use sqlx::PgPool;
use std::str::FromStr;

/// The password the migrator role actually holds, and keeps.
const MIGRATOR_STORED: &str = "pms1469-the-one-database-url-has";
/// What `MOKOSH_MIGRATOR_PASSWORD` has drifted to. Nothing may write this.
const MIGRATOR_DRIFTED: &str = "pms1469-the-one-the-env-var-says";
/// The app password being reconciled, which is the point of the pass.
const APP_NEW: &str = "pms1469-the-new-app-password";
const APP_OLD: &str = "pms1469-the-old-app-password";

/// A connection string for `role` with `password`, against the database this
/// test is already talking to. Same shape as PMS-1423's, so the suite works in
/// the dev container and on a runner without either knowing the other's host.
fn url_for(role: &str, password: &str) -> String {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL is set wherever this suite runs");
    let opts = PgConnectOptions::from_str(&base).expect("DATABASE_URL parses");
    format!(
        "postgres://{role}:{password}@{}:{}/{}",
        opts.get_host(),
        opts.get_port(),
        opts.get_database().unwrap_or("postgres"),
    )
}

/// Create a login role with a known password and CONNECT on this database.
///
/// Uuid-named, as PMS-1423 learned the hard way: roles are CLUSTER-wide while
/// the test database is not, so a name derived from the database collides with
/// whatever an interrupted run left behind.
async fn create_role(pool: &PgPool, password: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let role = format!("pms1469_{}", &id[..16]);
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{}'",
        password.replace('\'', "''")
    ))
    .execute(pool)
    .await
    .expect("this suite needs a role-creating connection, which the dev container's is");
    let db = current_database(pool).await;
    sqlx::query(&format!("GRANT CONNECT ON DATABASE \"{db}\" TO {role}"))
        .execute(pool)
        .await
        .expect("grant connect");
    role
}

async fn current_database(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("read the database name")
}

/// Drop the role, revoking what it holds first: the GRANT above is a dependency
/// and a bare `DROP ROLE` answers 2BP01, leaving a cluster-wide role behind.
/// Best-effort, so a cleanup failure cannot mask the assertion.
async fn drop_role(pool: &PgPool, role: &str) {
    if let Ok(db) = sqlx::query_scalar::<_, String>("SELECT current_database()")
        .fetch_one(pool)
        .await
    {
        let _ = sqlx::query(&format!("REVOKE ALL ON DATABASE \"{db}\" FROM {role}"))
            .execute(pool)
            .await;
    }
    let _ = sqlx::query(&format!("DROP OWNED BY {role}"))
        .execute(pool)
        .await;
    if let Err(e) = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await
    {
        eprintln!("PMS-1469: left role {role} behind ({e}); drop it by hand if it accumulates");
    }
}

/// The regression: run the real `AppPasswordMismatch` statement list, then ask
/// Postgres whether the migrator's original credential still authenticates.
///
/// One test over both roles, because the assertion is a relationship: the pass
/// has to change one password and leave the other alone. Split in two, the
/// "migrator survived" half would also pass against a provisioner that did
/// nothing at all.
#[mokosh_test]
async fn reconciling_the_app_password_leaves_the_migrator_credential_working(pool: PgPool) {
    let migrator = create_role(&pool, MIGRATOR_STORED).await;
    let app = create_role(&pool, APP_OLD).await;
    let db = current_database(&pool).await;

    // Precondition, so a later pass cannot be read as a success that was true
    // from the start.
    assert_eq!(
        app_login_with(&url_for(&app, APP_NEW)).await,
        AppLogin::WrongPassword,
        "the app role starts out NOT holding the configured password; that is the state being healed"
    );

    let stmts = provision_statements(
        &RolesProbe::AppPasswordMismatch,
        RoleNames::new(&migrator, &app),
        // Set, and wrong. The old code fed exactly this into
        // `ALTER ROLE <migrator> ... PASSWORD` and locked the role out.
        Some(MIGRATOR_DRIFTED),
        APP_NEW,
        &db,
    )
    .expect("the app half does not need the migrator's password");

    for stmt in &stmts {
        sqlx::query(stmt)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("provisioning step failed ({e}): {stmt}"));
    }

    assert_eq!(
        app_login_with(&url_for(&app, APP_NEW)).await,
        AppLogin::Ok,
        "the pass has to do its job: mokosh_app now holds the configured password"
    );
    assert_eq!(
        app_login_with(&url_for(&migrator, MIGRATOR_STORED)).await,
        AppLogin::Ok,
        "this is the bug: the migrator's own working password was overwritten from the drifted \
         env var, so the NEXT boot could not connect with DATABASE_URL at all"
    );
    assert_eq!(
        app_login_with(&url_for(&migrator, MIGRATOR_DRIFTED)).await,
        AppLogin::WrongPassword,
        "and the drifted value was never written anywhere"
    );

    drop_role(&pool, &app).await;
    drop_role(&pool, &migrator).await;
}
