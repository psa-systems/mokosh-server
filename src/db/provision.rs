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
    match roles_probe(migrator_url).await {
        RolesProbe::BothExist => {
            tracing::info!(
                "DB roles already provisioned (mokosh_migrator + mokosh_app present); skipping role provisioning"
            );
            return Ok(());
        }
        RolesProbe::MigratorConnectsAppMissing => {
            tracing::warn!(
                "mokosh_migrator can connect but mokosh_app is missing; falling through to full provision via {ADMIN_DATABASE_URL_VAR}"
            );
        }
        RolesProbe::MigratorCannotConnect => {
            // Fall through to the full provision path.
        }
    }

    let admin_url = match std::env::var(ADMIN_DATABASE_URL_VAR) {
        Ok(url) if !url.is_empty() => url,
        _ => {
            // The migrator role does not connect and there are no admin
            // credentials to create it with. Fail loud now rather than let the
            // later request-pool connect fail with a bare auth error.
            return Err(AppError::Database(format!(
                "mokosh_migrator cannot connect and {ADMIN_DATABASE_URL_VAR} is unset; set \
                 {ADMIN_DATABASE_URL_VAR} to a privileged (superuser) connection string so the \
                 server can create the mokosh_migrator / mokosh_app roles on first boot"
            )));
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
        RolesProbe::BothExist
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

    #[test]
    fn quote_ident_doubles_embedded_double_quotes() {
        assert_eq!(quote_ident("mokosh"), "\"mokosh\"");
        assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
    }
}
