//! PMS-1423: the boot probe notices that `mokosh_app`'s password is not ours.
//!
//! Every probe before this one asked the MIGRATOR connection about `pg_roles`,
//! which answers whether the role exists and whether it may log in, and never
//! whether it logs in with the password this deployment holds. So a rotated or
//! newly added `MOKOSH_APP_PASSWORD` took the fast path, and the request pool
//! then failed with a bare `password authentication failed for user
//! "mokosh_app"` and the container restart-looped. nc-01 did exactly that on
//! 2026-09-29 at 12:45 UTC.
//!
//! What needs a real Postgres is the discrimination, because it is the whole
//! fix and it is a property of the server's answers rather than of our code: a
//! wrong password has to be told apart from a right one AND from every other
//! way a connection can fail. Getting the second half wrong is worse than the
//! bug: treating a timeout as a mismatch routes a healthy deployment into the
//! full provision path, which demands `MOKOSH_ADMIN_DATABASE_URL` and fails the
//! boot without it.
//!
//! Driven through `provision::app_login_with` against roles this suite creates,
//! rather than through `provision_roles`, because that reads process-global
//! environment and `cargo test` shares one process across threads.

mod common;

use mokosh_server::db::provision::{app_login_with, AppLogin};
use mokosh_test::mokosh_test;
use sqlx::postgres::PgConnectOptions;
use sqlx::PgPool;
use std::str::FromStr;

const PASSWORD: &str = "pms1423-the-stored-one";
const WRONG: &str = "pms1423-the-configured-one";

/// A connection string for `role` with `password`, against the database this
/// test is already talking to.
///
/// Built from `DATABASE_URL`'s own host, port and database rather than assumed,
/// so this works in the dev container and on a runner without either knowing
/// where the other's Postgres is.
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

/// Create a login role with a known password, returning its name.
///
/// Named with a fresh uuid rather than something derived from the database,
/// because roles are CLUSTER-wide while the test database is not: a derived name
/// collides with a leftover from an interrupted run, and a leftover is exactly
/// what an interrupted run leaves. The first version of this derived the name
/// from the database and then failed on the leftover's own privileges.
async fn create_role(pool: &PgPool, password: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let role = format!("pms1423_{}", &id[..16]);
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{}'",
        password.replace('\'', "''")
    ))
    .execute(pool)
    .await
    .expect("this suite needs a role-creating connection, which the dev container's is");
    // CONNECT so the right-password case fails for no OTHER reason: Postgres
    // checks the privilege after authenticating, and a 42501 there would read as
    // `Ok` through this probe and pass the assertion for the wrong reason.
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("read the database name");
    sqlx::query(&format!("GRANT CONNECT ON DATABASE \"{db}\" TO {role}"))
        .execute(pool)
        .await
        .expect("grant connect");
    role
}

/// Drop the role, revoking what it holds first.
///
/// The GRANT above is a dependency, so a bare `DROP ROLE` answers 2BP01
/// ("cannot be dropped because some objects depend on it") and leaves a
/// cluster-wide role behind for every later run to trip over. Best-effort
/// throughout: this is cleanup, and a failure here must not mask the assertion
/// the test exists for.
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
        eprintln!("PMS-1423: left role {role} behind ({e}); drop it by hand if it accumulates");
    }
}

/// The three answers that matter, against one real role.
///
/// One test rather than three, because what is being asserted is that they are
/// DIFFERENT from each other: a probe that returned the same verdict for all
/// three would pass three separate tests that each only checked their own case.
#[mokosh_test]
async fn a_wrong_password_is_told_apart_from_a_right_one_and_from_everything_else(pool: PgPool) {
    let role = create_role(&pool, PASSWORD).await;

    assert_eq!(
        app_login_with(&url_for(&role, PASSWORD)).await,
        AppLogin::Ok,
        "the password the role actually holds has to read as usable, or every healthy boot \
         would be routed into the full provision path"
    );

    assert_eq!(
        app_login_with(&url_for(&role, WRONG)).await,
        AppLogin::WrongPassword,
        "this is the state nc-01 was in: the role exists, it can log in, and not with ours"
    );

    // Not a wrong password: a database that is not there. Postgres answers
    // 3D000, and treating that as a mismatch would demand admin credentials to
    // fix something admin credentials cannot fix.
    let missing_db = url_for(&role, PASSWORD).replace(
        &format!(
            "/{}",
            PgConnectOptions::from_str(&std::env::var("DATABASE_URL").unwrap())
                .unwrap()
                .get_database()
                .unwrap_or("postgres")
        ),
        "/pms1423_no_such_database",
    );
    assert_eq!(
        app_login_with(&missing_db).await,
        AppLogin::Ok,
        "only 28P01 is a password mismatch; everything else is somebody else's problem to \
         report, and the app pool reports it seconds later in its own words"
    );

    drop_role(&pool, &role).await;
}

/// A role that cannot log in at all is not reported as a password mismatch.
///
/// `NOLOGIN` is PMS-1163's state and it has its own probe answer and its own
/// operator message. If this probe claimed a mismatch for it, the boot error
/// would tell an operator to check `MOKOSH_APP_PASSWORD` for a role whose
/// password is irrelevant.
#[mokosh_test]
async fn a_nologin_role_is_not_a_password_mismatch(pool: PgPool) {
    let role = create_role(&pool, PASSWORD).await;
    sqlx::query(&format!("ALTER ROLE {role} NOLOGIN"))
        .execute(&pool)
        .await
        .expect("take LOGIN away");

    assert_ne!(
        app_login_with(&url_for(&role, PASSWORD)).await,
        AppLogin::WrongPassword,
        "NOLOGIN is PMS-1163's state, with its own message; the password is not the problem"
    );

    drop_role(&pool, &role).await;
}

/// No password reaches a log line, whatever the probe decides.
///
/// This is the acceptance criterion worth a real test rather than a code read:
/// the obvious way to write the failure branch is to log the error, and a
/// Postgres authentication error is one `{e}` away from putting a role name and
/// a connection string into the boot log of every deployment that hits this.
/// The probe therefore matches on SQLSTATE and logs the code, never the error.
#[mokosh_test]
async fn the_probe_never_logs_the_password(pool: PgPool) {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<String>>>);

    struct Collect(Captured);
    impl Visit for Collect {
        fn record_debug(&mut self, _f: &Field, value: &dyn std::fmt::Debug) {
            self.0 .0.lock().expect("lock").push(format!("{value:?}"));
        }
        fn record_str(&mut self, _f: &Field, value: &str) {
            self.0 .0.lock().expect("lock").push(value.to_string());
        }
    }

    struct CaptureLayer(Captured);
    impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            event.record(&mut Collect(self.0.clone()));
        }
    }

    let captured = Captured::default();
    let subscriber = tracing_subscriber::registry().with(CaptureLayer(captured.clone()));

    let role = create_role(&pool, PASSWORD).await;
    let wrong = url_for(&role, WRONG);
    let missing = url_for(&role, PASSWORD).replace("/mokosh", "/pms1423_no_such_database");

    // Both branches, under the capturing subscriber: the one that decides
    // "mismatch" and the one that decides "not our problem" and logs a reason.
    //
    // On its OWN thread with its OWN current-thread runtime, which is the part
    // worth explaining. `tracing`'s default subscriber is thread-local, and
    // this test's own runtime is multi-threaded, so a guard installed here would
    // not reliably cover work that resumes on another worker after an await. A
    // current-thread runtime pins the whole probe to the thread the guard is on.
    // The first attempt at this used `block_on` inside the async test instead
    // and deadlocked: blocking a tokio worker while awaiting a connection on the
    // same runtime is a hang, not a failure, which is the worse way to be wrong.
    let probe = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a current-thread runtime");
        let _guard = tracing::subscriber::set_default(subscriber);
        runtime.block_on(async {
            let _ = app_login_with(&wrong).await;
            let _ = app_login_with(&missing).await;
        });
    });
    probe.join().expect("the probe thread panicked");

    let lines = captured.0.lock().expect("lock").join("\n");
    for secret in [PASSWORD, WRONG] {
        assert!(
            !lines.contains(secret),
            "a password reached a log line: {lines}"
        );
    }
    assert!(
        !lines.contains(&role),
        "the role name travels with the connection string, so it is kept out too: {lines}"
    );

    drop_role(&pool, &role).await;
}
