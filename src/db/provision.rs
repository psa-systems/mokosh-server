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

/// PMS-1153: the roles a migration names, which therefore have to exist before
/// migrations run on every deployment shape.
///
/// `mokosh_app` alone, and on purpose. Migrations 207 and 210 grant to it;
/// nothing in `migrations/` references `mokosh_migrator`, and a deployment
/// that connects as a single role of its own does not use it, so requiring it
/// here would break exactly the deployments this exists for. This is the same
/// list `scripts/test-db-roles.sql` creates for CI, and a migration granting
/// to a new role means adding it to both.
pub const ROLES_REQUIRED_BY_MIGRATIONS: &[&str] = &["mokosh_app"];

/// What the probe connection learned about the database it reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleProbe {
    /// The role `DATABASE_URL` actually logged in as. Reported because the old
    /// log line claimed `mokosh_migrator` whenever anything connected.
    pub connected_as: String,
    /// Required roles that do not exist.
    pub missing: Vec<String>,
    /// Whether the connected role may create roles (`rolsuper` or
    /// `rolcreaterole`). A single-role deployment's role is usually the
    /// database superuser, which is what lets the fast path heal it.
    pub can_create_roles: bool,
}

/// PMS-1153: what to do in #746's [`RolesProbe::MigratorConnectsAppMissing`]
/// state - the migrator URL connected, `mokosh_app` does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRoleMissing {
    /// The admin credentials are there: #746's full provisioning path,
    /// unchanged. Preferred when available, because it creates the roles
    /// properly - a login, a password, the default privileges - where the
    /// branch below can only create a bare name.
    UseAdmin,
    /// No admin URL, but the role that connected may create roles (staging's
    /// single role is the database superuser): create the missing role
    /// `NOLOGIN` and carry on.
    CreateNoLogin,
    /// Neither. Refuse before migrations with a message that is TRUE for this
    /// state - the fall-through #746 routed here said "mokosh_migrator cannot
    /// connect", which is exactly what did not happen.
    Refuse(String),
}

/// PMS-1153: the whole decision for the app-role-missing state, as a pure
/// function so each branch is tested without a database.
pub fn decide_app_role_missing(
    admin_url_set: bool,
    can_create_roles: bool,
    connected_as: &str,
) -> AppRoleMissing {
    if admin_url_set {
        return AppRoleMissing::UseAdmin;
    }
    if can_create_roles {
        return AppRoleMissing::CreateNoLogin;
    }
    AppRoleMissing::Refuse(format!(
        "mokosh_app does not exist, and migrations grant to it (207, 210), so they would fail. \
         DATABASE_URL connects as `{connected_as}`, which cannot create roles, and \
         {ADMIN_DATABASE_URL_VAR} is unset. Either set {ADMIN_DATABASE_URL_VAR} to a superuser \
         connection string and restart, or run as a superuser: CREATE ROLE mokosh_app NOLOGIN;"
    ))
}

/// Ask the database the probe reached which role it is and which required
/// roles are missing. `required` is a parameter rather than the constant so a
/// test can probe for a role name nothing else uses.
pub async fn probe_roles(pool: &sqlx::PgPool, required: &[&str]) -> Result<RoleProbe, sqlx::Error> {
    let (connected_as, can_create_roles): (String, bool) = sqlx::query_as(
        "SELECT current_user::text, (rolsuper OR rolcreaterole) \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(pool)
    .await?;
    let present: Vec<String> =
        sqlx::query_scalar("SELECT rolname::text FROM pg_roles WHERE rolname = ANY($1)")
            .bind(required)
            .fetch_all(pool)
            .await?;
    let missing = required
        .iter()
        .filter(|r| !present.iter().any(|p| p == *r))
        .map(|r| r.to_string())
        .collect();
    Ok(RoleProbe {
        connected_as,
        missing,
        can_create_roles,
    })
}

/// Create each role `NOLOGIN` if it is still absent. Idempotent: two replicas
/// booting at once may both decide to create it, and the loser's `CREATE`
/// must be a no-op rather than an error that stops its boot.
pub async fn create_nologin_roles(
    pool: &sqlx::PgPool,
    roles: &[String],
) -> Result<(), sqlx::Error> {
    for role in roles {
        let literal = sql_quote(role);
        let ident = quote_ident(role);
        sqlx::query(&format!(
            "DO $do$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {literal}) \
             THEN CREATE ROLE {ident} NOLOGIN; END IF; END $do$"
        ))
        .execute(pool)
        .await?;
    }
    Ok(())
}

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
        RolesProbe::BothExist { connected_as } => {
            tracing::info!(
                connected_as = %connected_as,
                "DB roles present (mokosh_app exists); skipping role provisioning"
            );
            return Ok(());
        }
        RolesProbe::MigratorConnectsAppMissing {
            connected_as,
            can_create_roles,
        } => {
            let admin_url_set = std::env::var(ADMIN_DATABASE_URL_VAR)
                .map(|url| !url.is_empty())
                .unwrap_or(false);
            match decide_app_role_missing(admin_url_set, can_create_roles, &connected_as) {
                AppRoleMissing::UseAdmin => {
                    tracing::warn!(
                        connected_as = %connected_as,
                        "mokosh_app is missing; falling through to full provision via {ADMIN_DATABASE_URL_VAR}"
                    );
                }
                AppRoleMissing::CreateNoLogin => {
                    // PMS-1153: a single-role deployment heals itself. The
                    // role is created NOLOGIN because a GRANT needs only that
                    // it exists, and nothing should be able to log in as a
                    // role an automatic step made.
                    tracing::warn!(
                        connected_as = %connected_as,
                        "mokosh_app is missing and {ADMIN_DATABASE_URL_VAR} is unset; creating it \
                         NOLOGIN so migrations that grant to it can run"
                    );
                    let pool = PgPoolOptions::new()
                        .max_connections(1)
                        .acquire_timeout(Duration::from_secs(10))
                        .connect(migrator_url)
                        .await
                        .map_err(|e| {
                            AppError::Database(format!("reconnect to create mokosh_app: {e}"))
                        })?;
                    let created = create_nologin_roles(
                        &pool,
                        &ROLES_REQUIRED_BY_MIGRATIONS
                            .iter()
                            .map(|r| r.to_string())
                            .collect::<Vec<_>>(),
                    )
                    .await;
                    pool.close().await;
                    created.map_err(|e| {
                        AppError::Database(format!("failed to create mokosh_app NOLOGIN: {e}"))
                    })?;
                    return Ok(());
                }
                AppRoleMissing::Refuse(message) => return Err(AppError::Database(message)),
            }
        }
        RolesProbe::MigratorCannotConnect => {
            // Fall through to the full provision path. With the app-missing
            // state now decided above, the admin-unset error below is only
            // reached from here, where "mokosh_migrator cannot connect" is
            // true again.
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
/// and does the `mokosh_app` role exist in `pg_roles`?
///
/// [`RolesProbe::BothExist`] is the fast path a healthy deployment takes on
/// every subsequent boot. [`RolesProbe::MigratorConnectsAppMissing`] is the
/// state staging hit on 2026-09-10, where the migrator was fine but every
/// GRANT to `mokosh_app` in a new migration failed. [`RolesProbe::MigratorCannotConnect`]
/// is the first-boot state, or a deployment that has never provisioned the
/// split roles.
///
/// PMS-1153 added what each connected state learned: the role that ACTUALLY
/// logged in (staging's `DATABASE_URL` is a single role of its own, not
/// `mokosh_migrator`, and the log used to claim otherwise) and whether that
/// role may create roles.
enum RolesProbe {
    BothExist {
        connected_as: String,
    },
    MigratorConnectsAppMissing {
        connected_as: String,
        can_create_roles: bool,
    },
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
    // needing admin credentials.
    let probe = probe_roles(&pool, ROLES_REQUIRED_BY_MIGRATIONS).await;
    pool.close().await;

    match probe {
        Ok(probe) if probe.missing.is_empty() => RolesProbe::BothExist {
            connected_as: probe.connected_as,
        },
        Ok(probe) => RolesProbe::MigratorConnectsAppMissing {
            connected_as: probe.connected_as,
            can_create_roles: probe.can_create_roles,
        },
        Err(e) => {
            // #746's rule, kept: a probe that cannot answer is "we cannot
            // confirm", never "the role is there". It cannot vouch for being
            // able to create roles either, so the self-heal is off for it.
            tracing::warn!("mokosh_app existence probe failed: {e}");
            RolesProbe::MigratorConnectsAppMissing {
                connected_as: "unknown (probe failed)".to_string(),
                can_create_roles: false,
            }
        }
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

    /// PMS-1153: #746's admin path stays the first choice when it is
    /// available, because it creates the roles properly - a login, a
    /// password, the default privileges.
    #[test]
    fn the_admin_path_wins_when_it_is_available() {
        assert_eq!(
            decide_app_role_missing(true, true, "mokosh"),
            AppRoleMissing::UseAdmin
        );
        assert_eq!(
            decide_app_role_missing(true, false, "mokosh"),
            AppRoleMissing::UseAdmin
        );
    }

    /// Staging's shape: a single role of its own that is the database
    /// superuser, and no admin URL. It heals by creating the role NOLOGIN,
    /// where #746 alone would have stopped boot and asked for credentials.
    #[test]
    fn a_role_that_may_create_roles_heals_the_deployment() {
        assert_eq!(
            decide_app_role_missing(false, true, "mokosh"),
            AppRoleMissing::CreateNoLogin
        );
    }

    /// Nothing can create it: refuse, and say what is TRUE. The fall-through
    /// this state used to reach claimed "mokosh_migrator cannot connect",
    /// which is exactly what had not happened.
    #[test]
    fn a_role_that_cannot_create_roles_is_refused_truthfully() {
        let AppRoleMissing::Refuse(message) = decide_app_role_missing(false, false, "mokosh")
        else {
            panic!("expected a refusal");
        };
        assert!(message.contains("mokosh_app does not exist"), "{message}");
        assert!(
            message.contains("`mokosh`"),
            "names who connected: {message}"
        );
        assert!(
            message.contains("CREATE ROLE mokosh_app NOLOGIN;"),
            "gives the SQL: {message}"
        );
        assert!(
            !message.contains("cannot connect"),
            "the connection succeeded, so the message must not say it failed: {message}"
        );
    }

    /// The roles the fast path guarantees are the ones CI creates for the
    /// Postgres-backed suite, and `mokosh_migrator` is deliberately not one:
    /// no migration names it and a single-role deployment does not use it.
    #[test]
    fn the_required_roles_are_the_ones_migrations_grant_to() {
        assert_eq!(ROLES_REQUIRED_BY_MIGRATIONS, &["mokosh_app"]);
        let ci = include_str!("../../scripts/test-db-roles.sql");
        for role in ROLES_REQUIRED_BY_MIGRATIONS {
            assert!(
                ci.contains(&format!("CREATE ROLE {role}")),
                "CI's role list and the provisioner's must agree on {role}"
            );
        }
    }

    #[test]
    fn quote_ident_doubles_embedded_double_quotes() {
        assert_eq!(quote_ident("mokosh"), "\"mokosh\"");
        assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
    }
}
