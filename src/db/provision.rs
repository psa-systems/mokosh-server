//! PMS-489: self-provision the split DB roles at server startup.
//!
//! This supersedes the two divergent mechanisms it replaces - the dev
//! `scripts/pg-init.sh` initdb script and the prod `mokosh-bootstrap
//! provision-roles` CLI step - with a single mechanism that is identical in
//! dev and prod and driven only by environment variables.
//!
//! Before connecting the request pools and running migrations, the server
//! checks whether the `mokosh_migrator` role can already log in. If it can,
//! provisioning is skipped entirely, so production may drop the privileged
//! admin credentials after the first boot. If it cannot, the server connects
//! with the privileged `MOKOSH_ADMIN_DATABASE_URL` and idempotently creates
//! the two roles:
//!
//! - `mokosh_migrator` (`LOGIN BYPASSRLS`) owns the schema and runs DDL /
//!   migrations / bootstrap. It is also granted `CREATE ON DATABASE` so the
//!   migrations can self-install the (trusted) `uuid-ossp` / `pg_trgm` /
//!   `citext` / `pgcrypto` extensions (`migrations/002_tenants.sql`) - the
//!   grant the old `provision-roles` step omitted.
//! - `mokosh_app` (`LOGIN NOSUPERUSER NOBYPASSRLS`) is the request-serving
//!   role. It is granted connect/usage/DML on the current objects plus
//!   `ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator` so objects created by
//!   future migrations auto-grant to it. It owns nothing, so RLS bites it.
//!
//! The admin pool is closed immediately after provisioning. The role names are
//! fixed identifiers (no injection surface); the passwords are interpolated as
//! SQL string literals because the utility statements (`CREATE`/`ALTER ROLE`)
//! cannot take bind parameters, so embedded quotes are doubled.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;

use crate::utils::error::{AppError, AppResult};

/// Privileged (superuser / DB-owner) connection string used once to create the
/// split roles. Optional: when it is unset and the migrator role already
/// connects, provisioning is a no-op.
const ADMIN_DATABASE_URL_VAR: &str = "MOKOSH_ADMIN_DATABASE_URL";
/// Password set on the `mokosh_migrator` role when it is created.
const MIGRATOR_PASSWORD_VAR: &str = "MOKOSH_MIGRATOR_PASSWORD";
/// Password set on the `mokosh_app` role when it is created.
const APP_PASSWORD_VAR: &str = "MOKOSH_APP_PASSWORD";
/// The connection string the request pool authenticates as `mokosh_app` with.
/// Read here, not through the config seam, for the reason every other var in
/// this file is: provisioning runs before configuration is built. Unset means
/// the request pool uses `DATABASE_URL` too (`db::pool`), so there is no second
/// credential to get wrong and the mismatch probe below is skipped.
const APP_DATABASE_URL_VAR: &str = "MOKOSH_APP_DATABASE_URL";
/// Postgres `invalid_password`. The ONLY error that means the stored password
/// and the configured one disagree; anything else is a different problem and is
/// not reported as this one.
const INVALID_PASSWORD: &str = "28P01";

/// Create the `mokosh_migrator` / `mokosh_app` roles if they do not yet exist.
///
/// `migrator_url` is the migrator connection string (`DATABASE_URL`). When a
/// login with it succeeds the roles already exist and this is a no-op. When it
/// fails the function connects with `MOKOSH_ADMIN_DATABASE_URL` and creates the
/// roles idempotently, then closes the admin pool. Call this once at startup,
/// before [`super::Database::new`] and migrations.
pub async fn provision_roles(migrator_url: &str) -> AppResult<()> {
    // Fast path: the migrator role can log in AND `mokosh_app` exists. Both
    // halves matter: staging on 2026-09-10 hit "role \"mokosh_app\" does not
    // exist" on migration 207's closing GRANT because the fast path had
    // returned early on migrator-can-connect alone. The migrator being there
    // does not imply the app role is - a database provisioned before the
    // PMS-489 split, or one where the app role was manually dropped, leaves
    // the migrator functional while every future GRANT to mokosh_app fails.
    // Checking both here catches that state before migrations run and
    // routes it to the full provision path, which needs
    // MOKOSH_ADMIN_DATABASE_URL to recreate what is missing.
    // PMS-1153: the messages below say what happened, not what was assumed.
    // `DATABASE_URL` is not necessarily `mokosh_migrator` - staging connected
    // as a single role of its own - so no line claims the migrator connected,
    // and the probe logs which role actually did.
    let probe = roles_probe(migrator_url).await;
    match probe {
        RolesProbe::BothExist => {
            tracing::info!("mokosh_app present and able to log in; skipping role provisioning");
            return Ok(());
        }
        RolesProbe::MigratorConnectsAppMissing => {
            tracing::warn!(
                "DATABASE_URL connects but mokosh_app is missing or cannot log in; falling through to full provision via {ADMIN_DATABASE_URL_VAR}"
            );
        }
        RolesProbe::AppPasswordMismatch => {
            // Falls through to the same full provision path, which already
            // ends with `ALTER ROLE mokosh_app ... PASSWORD`, so the
            // reconciliation is the existing statement rather than a new one.
            // Named separately only because the operator-facing message for a
            // wrong password is not the message for a missing role.
            tracing::warn!(
                "mokosh_app exists but {APP_DATABASE_URL_VAR} cannot authenticate as it; \
                 reconciling its password from {APP_PASSWORD_VAR} via {ADMIN_DATABASE_URL_VAR}"
            );
        }
        RolesProbe::MigratorCannotConnect => {
            // Fall through to the full provision path.
        }
    }

    let admin_url = match std::env::var(ADMIN_DATABASE_URL_VAR) {
        Ok(url) if !url.is_empty() => url,
        _ => {
            // No admin credentials to create or reconcile the roles with. Fail
            // loud now rather than let the later request-pool connect fail with
            // a bare auth error.
            return Err(AppError::Database(admin_unset_message(&probe)));
        }
    };

    let migrator_password = require_env(MIGRATOR_PASSWORD_VAR)?;
    let app_password = require_env(APP_PASSWORD_VAR)?;

    tracing::info!(
        "mokosh_migrator cannot connect; provisioning DB roles via {ADMIN_DATABASE_URL_VAR}"
    );

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&admin_url)
        .await
        .map_err(|e| {
            AppError::Database(format!(
                "failed to connect with {ADMIN_DATABASE_URL_VAR}: {e}"
            ))
        })?;

    let db_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::Database(format!("failed to read current_database(): {e}")))?;

    let migrator_pw = sql_quote(&migrator_password);
    let app_pw = sql_quote(&app_password);
    let db = quote_ident(&db_name);

    // CREATE ROLE is not idempotent, so guard each with a DO block; the ALTER
    // ROLE afterwards reconciles the password + attributes on an existing role.
    let stmts: Vec<String> = vec![
        format!(
            "DO $do$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mokosh_migrator') \
             THEN CREATE ROLE mokosh_migrator LOGIN BYPASSRLS PASSWORD {migrator_pw}; END IF; END $do$"
        ),
        format!("ALTER ROLE mokosh_migrator LOGIN BYPASSRLS PASSWORD {migrator_pw}"),
        format!(
            "DO $do$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mokosh_app') \
             THEN CREATE ROLE mokosh_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {app_pw}; END IF; END $do$"
        ),
        format!("ALTER ROLE mokosh_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {app_pw}"),
        // The migrator owns/creates schema objects.
        "GRANT ALL ON SCHEMA public TO mokosh_migrator".to_string(),
        // CREATE on the database lets the migrator self-install the trusted
        // extensions (CREATE EXTENSION). The old provision-roles step omitted
        // this, so the migrator could not.
        format!("GRANT CREATE ON DATABASE {db} TO mokosh_migrator"),
        // The app role: connect + use the schema, read/write existing objects.
        format!("GRANT CONNECT ON DATABASE {db} TO mokosh_app"),
        "GRANT USAGE ON SCHEMA public TO mokosh_app".to_string(),
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mokosh_app"
            .to_string(),
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mokosh_app".to_string(),
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mokosh_app".to_string(),
        // Future objects created by the migrator are auto-granted to the app.
        "ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator IN SCHEMA public \
         GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mokosh_app"
            .to_string(),
        "ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator IN SCHEMA public \
         GRANT USAGE, SELECT ON SEQUENCES TO mokosh_app"
            .to_string(),
        "ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator IN SCHEMA public \
         GRANT EXECUTE ON FUNCTIONS TO mokosh_app"
            .to_string(),
    ];

    for stmt in &stmts {
        sqlx::query(stmt).execute(&pool).await.map_err(|e| {
            AppError::Database(format!("role provisioning step failed ({e}): {stmt}"))
        })?;
    }

    // Close the privileged pool promptly: the admin URL is only needed for this
    // one-time step and must not linger as an open superuser connection.
    pool.close().await;

    tracing::info!(
        database = %db_name,
        "DB roles provisioned (mokosh_migrator BYPASSRLS / mokosh_app NOSUPERUSER NOBYPASSRLS)"
    );
    Ok(())
}

/// The result of the boot-time role probe: does the migrator role log in,
/// and can the `mokosh_app` role log in?
///
/// [`RolesProbe::BothExist`] is the fast path a healthy deployment takes on
/// every subsequent boot. [`RolesProbe::MigratorConnectsAppMissing`] is the
/// state staging hit on 2026-09-10, where the migrator was fine but every
/// GRANT to `mokosh_app` in a new migration failed. [`RolesProbe::MigratorCannotConnect`]
/// is the first-boot state, or a deployment that has never provisioned the
/// split roles.
///
/// PMS-1163: `MigratorConnectsAppMissing` also fires when the `mokosh_app`
/// row exists but is `NOLOGIN`. That is what staging landed in after
/// PMS-1152 hand-created the role to unblock migration 207's GRANT: the
/// row was present so the pre-PMS-1163 probe returned `BothExist` and the
/// fast path skipped the `ALTER ROLE ... LOGIN ... PASSWORD` at line 133,
/// leaving the app pool unable to authenticate on the very next boot step.
/// Falling through when `rolcanlogin` is false routes to the full provision
/// path, whose ALTER heals the LOGIN + password state in one pass.
enum RolesProbe {
    BothExist,
    MigratorConnectsAppMissing,
    /// PMS-1423: `mokosh_app` exists and can log in, but not with the password
    /// this deployment is configured to use.
    ///
    /// Invisible to every earlier probe, because all of them ask the MIGRATOR
    /// connection about `pg_roles` and never try to authenticate as the app
    /// role. A rotated or newly added `MOKOSH_APP_PASSWORD` therefore took the
    /// fast path, and the request pool then failed with a bare
    /// `password authentication failed for user "mokosh_app"` and the container
    /// restart-looped, which is what nc-01 did on 2026-09-29 at 12:45 UTC.
    AppPasswordMismatch,
    MigratorCannotConnect,
}

async fn roles_probe(migrator_url: &str) -> RolesProbe {
    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(migrator_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            tracing::debug!("mokosh_migrator probe connection failed: {e}");
            return RolesProbe::MigratorCannotConnect;
        }
    };

    // PMS-1153: say which role DATABASE_URL actually logged in as. Staging's
    // was a single role of its own, and the boot log used to name
    // `mokosh_migrator` regardless. Best-effort: a probe that cannot read
    // `current_user` still goes on to answer the question it exists for.
    if let Ok(connected_as) = sqlx::query_scalar::<_, String>("SELECT current_user::text")
        .fetch_one(&pool)
        .await
    {
        tracing::info!(connected_as = %connected_as, "DB role probe connected with DATABASE_URL");
    }

    // pg_roles is a public view of pg_authid: readable by every logged-in
    // role without extra grants, so the migrator can answer this without
    // needing admin credentials. PMS-1163: the predicate carries
    // `rolcanlogin = TRUE` alongside the name check so a hand-created
    // NOLOGIN mokosh_app falls through to the full provision path (whose
    // ALTER ROLE reconciles both attributes and the stored password with
    // MOKOSH_APP_PASSWORD in one pass), rather than tripping the fast
    // path and failing the app pool's auth attempt on the next boot step.
    let app_can_login: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mokosh_app' AND rolcanlogin = TRUE)",
    )
    .fetch_one(&pool)
    .await
    .unwrap_or_else(|e| {
        // If the probe query itself fails, treat it as "we cannot confirm"
        // and fall through to full provision, which will name the underlying
        // error if the admin URL is unset.
        tracing::warn!("mokosh_app existence probe failed: {e}");
        false
    });
    pool.close().await;

    if app_can_login {
        // PMS-1423: `pg_roles` says the role can log in. It does NOT say it can
        // log in with OUR password, and nothing before this ever asked. So ask,
        // once, with the credential the request pool is about to use.
        match app_password_matches().await {
            AppLogin::Unconfigured | AppLogin::Ok => RolesProbe::BothExist,
            AppLogin::WrongPassword => RolesProbe::AppPasswordMismatch,
        }
    } else {
        // Covers both "row missing" and "row exists but NOLOGIN". The
        // downstream branch runs the same ALTER either way, so one variant
        // covers both, but log the reason so an operator reading the boot
        // log knows which state the deployment was in.
        tracing::info!(
            "mokosh_app row missing or cannot log in; falling through to full provision via {ADMIN_DATABASE_URL_VAR}"
        );
        RolesProbe::MigratorConnectsAppMissing
    }
}

/// What one authentication attempt as `mokosh_app` told us (PMS-1423).
#[derive(Debug, PartialEq, Eq)]
pub enum AppLogin {
    /// `MOKOSH_APP_DATABASE_URL` is unset, so the request pool shares
    /// `DATABASE_URL` and there is no second credential to disagree.
    Unconfigured,
    /// It authenticated, so the stored password is the configured one.
    Ok,
    /// Postgres answered `28P01`.
    WrongPassword,
}

/// Try one connection with `MOKOSH_APP_DATABASE_URL`.
///
/// Deliberately narrow: ONLY `28P01` counts as a mismatch. Every other failure
/// is reported as `Ok`, which reads backwards until you consider what the
/// alternative costs. A timeout, an unreachable host, a missing database or a
/// `too many connections` would otherwise route a healthy deployment into the
/// full provision path, which demands `MOKOSH_ADMIN_DATABASE_URL` and fails the
/// boot when it is absent. That turns a transient blip into an outage, for a
/// condition this function was not asked about. The migrator connected moments
/// ago, so the host is reachable; anything that is not a wrong password is
/// somebody else's problem to report, and the app pool will report it in its own
/// words seconds later.
///
/// The password is never logged. The error is matched on its SQLSTATE rather
/// than its text for the same reason: a Postgres auth error renders the role
/// name and the message, and formatting the whole thing into a log line is how
/// a credential ends up in one.
async fn app_password_matches() -> AppLogin {
    match std::env::var(APP_DATABASE_URL_VAR) {
        Ok(url) if !url.trim().is_empty() => app_login_with(&url).await,
        _ => AppLogin::Unconfigured,
    }
}

/// The attempt itself, against an explicit URL.
///
/// Split from the env read so it can be driven against a real Postgres role
/// without a test writing to process-global environment, which this repository
/// avoids because `cargo test` shares one process across threads. The `from_env`
/// / `resolve` split in `config` and `app_secrets` is the same shape.
///
/// `pub` rather than `pub(crate)` for the reason `AppSecrets::with_provider` is
/// (PMS-1441): the test that matters here drives a REAL Postgres role, so it is
/// an integration test, and an integration test links the library compiled
/// without `cfg(test)`. The startup path does not call this directly; it goes
/// through [`app_password_matches`].
pub async fn app_login_with(url: &str) -> AppLogin {
    match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url)
        .await
    {
        Ok(pool) => {
            pool.close().await;
            AppLogin::Ok
        }
        Err(e) => {
            let sqlstate = match &e {
                sqlx::Error::Database(db) => db.code().map(|c| c.to_string()),
                _ => None,
            };
            if sqlstate.as_deref() == Some(INVALID_PASSWORD) {
                AppLogin::WrongPassword
            } else {
                // Named by code, not by rendering the error, so no connection
                // string or credential reaches the log through this path.
                tracing::debug!(
                    sqlstate = sqlstate.as_deref().unwrap_or("none"),
                    "mokosh_app login probe failed for a reason other than a wrong password; \
                     treating the role as usable and leaving the app pool to report it"
                );
                AppLogin::Ok
            }
        }
    }
}

/// PMS-1153: the error when role provisioning is needed and
/// `MOKOSH_ADMIN_DATABASE_URL` is unset, told truthfully for each state.
///
/// Before this there was one message for both, and it said "mokosh_migrator
/// cannot connect" - true on first boot, and false in exactly the state
/// staging reached in September 2026, where `DATABASE_URL` connected fine and
/// `mokosh_app` was the thing missing (and, after PMS-1163, present but
/// `NOLOGIN`). An operator told the wrong problem fixes the wrong thing.
fn admin_unset_message(probe: &RolesProbe) -> String {
    match probe {
        // PMS-1423: a wrong password is not a missing role, and telling an
        // operator to create `mokosh_app` when it already exists sends them to
        // check the one thing that is fine. This names the two variables whose
        // disagreement caused it.
        RolesProbe::AppPasswordMismatch => format!(
            "mokosh_app exists and can log in, but {APP_PASSWORD_VAR} is not the password it \
             holds, so the request pool would fail with a bare authentication error; set \
             {ADMIN_DATABASE_URL_VAR} to a privileged (superuser) connection string and the next \
             boot reconciles the role's password from {APP_PASSWORD_VAR}, or set \
             {APP_PASSWORD_VAR} to the password the role already has"
        ),
        RolesProbe::MigratorConnectsAppMissing => format!(
            "DATABASE_URL connects, but mokosh_app is missing or cannot log in, and \
             {ADMIN_DATABASE_URL_VAR} is unset; set {ADMIN_DATABASE_URL_VAR} to a privileged \
             (superuser) connection string so the server can create mokosh_app, or reconcile \
             an existing one to LOGIN with {APP_PASSWORD_VAR}. A hand-created NOLOGIN \
             mokosh_app is not enough when {APP_DATABASE_URL_VAR} logs in as it."
        ),
        RolesProbe::BothExist | RolesProbe::MigratorCannotConnect => format!(
            "mokosh_migrator cannot connect and {ADMIN_DATABASE_URL_VAR} is unset; set \
             {ADMIN_DATABASE_URL_VAR} to a privileged (superuser) connection string so the \
             server can create the mokosh_migrator / mokosh_app roles on first boot"
        ),
    }
}

fn require_env(key: &str) -> AppResult<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(AppError::Database(format!(
            "{key} is required to provision DB roles but is unset"
        ))),
    }
}

/// Quote a string as a single-quoted SQL literal, doubling embedded quotes.
fn sql_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Quote an SQL identifier, doubling embedded double-quotes.
fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_quote_doubles_embedded_single_quotes() {
        assert_eq!(sql_quote("plain"), "'plain'");
        assert_eq!(sql_quote("o'brien"), "'o''brien'");
        assert_eq!(sql_quote("'; DROP ROLE --"), "'''; DROP ROLE --'");
    }

    /// PMS-1153: the admin-unset error tells the truth for each probe state.
    /// The state where DATABASE_URL connected used to be told it had not,
    /// which is exactly the state staging reached.
    #[test]
    fn the_admin_unset_error_does_not_say_a_connection_failed_when_it_did_not() {
        let connected = admin_unset_message(&RolesProbe::MigratorConnectsAppMissing);
        assert!(!connected.contains("cannot connect"), "{connected}");
        assert!(
            connected.contains("mokosh_app is missing or cannot log in"),
            "{connected}"
        );
        assert!(connected.contains("NOLOGIN"), "names the trap: {connected}");
        assert!(connected.contains(ADMIN_DATABASE_URL_VAR), "{connected}");

        let first_boot = admin_unset_message(&RolesProbe::MigratorCannotConnect);
        assert!(
            first_boot.contains("mokosh_migrator cannot connect"),
            "{first_boot}"
        );

        // PMS-1423: the third state. A wrong password is not a missing role,
        // and the message that says "mokosh_app is missing" sends an operator
        // to check the one thing that is fine. It has to name both variables
        // whose disagreement caused it, because fixing either one resolves it
        // and only the operator knows which is right.
        let mismatch = admin_unset_message(&RolesProbe::AppPasswordMismatch);
        assert!(
            mismatch.contains(APP_PASSWORD_VAR) && mismatch.contains(ADMIN_DATABASE_URL_VAR),
            "names both variables: {mismatch}"
        );
        assert!(
            !mismatch.contains("missing") && !mismatch.contains("cannot connect"),
            "the role is present and connectable; saying otherwise is the PMS-1153 mistake \
             again: {mismatch}"
        );
        for other in [
            admin_unset_message(&RolesProbe::MigratorConnectsAppMissing),
            admin_unset_message(&RolesProbe::MigratorCannotConnect),
        ] {
            assert_ne!(
                other, mismatch,
                "each probe state gets its own sentence, or the operator is told the wrong problem"
            );
        }
    }

    #[test]
    fn quote_ident_doubles_embedded_double_quotes() {
        assert_eq!(quote_ident("mokosh"), "\"mokosh\"");
        assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
    }

    /// PMS-1265: a migration that creates a table grants it to `mokosh_app`
    /// in the same file.
    ///
    /// The provisioner only reaches the app role for tables `mokosh_migrator`
    /// creates (default privileges) or that exist at a full provision. A
    /// deployment whose migrations run as another owner, which staging's do,
    /// leaves every later table invisible to the app pool: that is how
    /// contact create and list went 500 there with `permission denied for
    /// table contact_sync_links`. Migration 235 healed every table up to it;
    /// this keeps the next one from repeating it. Earlier migrations are
    /// immutable and covered by 235, so only those after it are read.
    #[test]
    fn every_new_table_is_granted_to_the_app_role() {
        const HEALED_UP_TO: u32 = 235;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut read = 0;
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("read migrations") {
            let path = entry.expect("entry").path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(number) = name.split('_').next().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            read += 1;
            if number <= HEALED_UP_TO {
                continue;
            }
            let sql = std::fs::read_to_string(&path)
                .expect("read migration")
                .to_lowercase();
            let code: String = sql
                .lines()
                .map(|l| l.split("--").next().unwrap_or_default())
                .collect::<Vec<_>>()
                .join("\n");
            for created in code.split("create table").skip(1) {
                let table = created
                    .trim_start()
                    .trim_start_matches("if not exists")
                    .trim_start()
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                    .next()
                    .unwrap_or_default()
                    .trim_start_matches("public.")
                    .to_string();
                let granted = code.split("grant").skip(1).any(|g| {
                    let statement = g.split(';').next().unwrap_or_default();
                    statement.contains("to mokosh_app")
                        && (statement.contains(&format!(" {table} "))
                            || statement.contains(&format!(" {table},"))
                            || statement.contains(&format!(",{table} "))
                            || statement.contains(&format!(" {table}\n"))
                            || statement.contains("all tables in schema public"))
                });
                if !granted {
                    offenders.push(format!("{name}: {table}"));
                }
            }
        }
        assert!(
            read > HEALED_UP_TO as usize / 2,
            "only {read} migrations were read"
        );
        assert!(
            offenders.is_empty(),
            "these migrations create a table without `GRANT SELECT, INSERT, UPDATE, DELETE ON <table> TO mokosh_app;` in the same file, so a deployment whose migrations run as another owner cannot read it (PMS-1265):\n{}",
            offenders.join("\n")
        );
    }
}
