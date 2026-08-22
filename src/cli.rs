//! Operator subcommands folded into the `mokosh-server` binary (PMS-494).
//!
//! Three operator features used to live only in the standalone
//! `mokosh-bootstrap` binary (`src/bin/mokosh-bootstrap.rs`). PMS-494 folded them
//! into the main binary, so they are now reachable as `mokosh-server <subcommand>`
//! (the standalone binary still exists and dispatches its own subcommand set,
//! which overlaps this one without matching it: see `print_help` there):
//!
//! - `bootstrap-infisical`        - first-run setup of a fresh Infisical
//!   instance (core logic in [`crate::infisical::run_dev_bootstrap`]).
//! - `qa-seed` / `qa-teardown`    - load / remove the QA walkthrough dataset
//!   (PMS-331), fail-closed against any tenant not explicitly marked QA.
//! - `showcase-seed` / `showcase-refresh` / `showcase-teardown` - create,
//!   reset, or remove the richer showcase demo dataset (PMS-620), fail-closed
//!   against any tenant not explicitly marked `is_showcase`.
//!
//! The former `clients register` subcommand (which registered an OAuth client
//! in `mokosh_auth.oauth_clients`) was removed with mokosh-auth in PMS-295;
//! bunyip is now the sole OP and owns its own client registry.
//!
//! [`crate::main`] (the `mokosh-server` binary) inspects argv before starting
//! the HTTP server: when the first token is one of these subcommands (see
//! [`is_subcommand`]) it runs the task and exits instead of serving. Each
//! feature keeps its original env-var contract and fail-closed guards.
//!
//! `provision-roles` is intentionally NOT here: it moved into normal server
//! startup under PMS-489 (see [`crate::db::provision`]).

use std::path::PathBuf;

use crate::infisical::{run_dev_bootstrap, BootstrapInput, DevBootstrapConfig};

const DEFAULT_URL: &str = "http://localhost:28002";
const DEFAULT_PROJECT_NAME: &str = "mokosh";
const DEFAULT_IDENTITY_NAME: &str = "mokosh-machine";
const DEFAULT_ENVIRONMENT: &str = "dev";
const DEFAULT_ENV_FILE: &str = ".env";
const DEFAULT_ADMIN_FIRST_NAME: &str = "Mokosh";
const DEFAULT_ADMIN_LAST_NAME: &str = "Admin";

/// Whether `name` (argv's first token) selects an operator subcommand handled
/// by [`run`] rather than the long-running HTTP server. The caller starts the
/// server when this returns `false`.
pub fn is_subcommand(name: &str) -> bool {
    matches!(
        name,
        "bootstrap-infisical"
            | "qa-seed"
            | "qa-teardown"
            | "showcase-seed"
            | "showcase-refresh"
            | "showcase-teardown"
    )
}

/// Dispatch the operator subcommand named by `args[1]` (so `args` is the full
/// argv). Only call this when [`is_subcommand`] returned true for `args[1]`.
/// Returns `Ok(())` on success; the caller maps an `Err` to a non-zero exit.
pub async fn run(args: &[String]) -> anyhow::Result<()> {
    match args.get(1).map(String::as_str) {
        Some("bootstrap-infisical") => run_bootstrap_infisical().await,
        Some("qa-seed") => run_qa("qa-seed", args).await,
        Some("qa-teardown") => run_qa("qa-teardown", args).await,
        Some("showcase-seed") => run_showcase("showcase-seed", args).await,
        Some("showcase-refresh") => run_showcase("showcase-refresh", args).await,
        Some("showcase-teardown") => run_showcase("showcase-teardown", args).await,
        other => anyhow::bail!("not an operator subcommand: {other:?}"),
    }
}

// --- bootstrap-infisical --------------------------------------------------

async fn run_bootstrap_infisical() -> anyhow::Result<()> {
    let admin_email = require_env("INFISICAL_ADMIN_EMAIL")?;
    let admin_password = require_env("INFISICAL_ADMIN_PASSWORD")?;
    let admin_first_name = std::env::var("INFISICAL_ADMIN_FIRST_NAME")
        .unwrap_or_else(|_| DEFAULT_ADMIN_FIRST_NAME.to_string());
    let admin_last_name = std::env::var("INFISICAL_ADMIN_LAST_NAME")
        .unwrap_or_else(|_| DEFAULT_ADMIN_LAST_NAME.to_string());
    let url = std::env::var("INFISICAL_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let project_name = std::env::var("INFISICAL_PROJECT_NAME")
        .unwrap_or_else(|_| DEFAULT_PROJECT_NAME.to_string());
    let identity_name = std::env::var("INFISICAL_IDENTITY_NAME")
        .unwrap_or_else(|_| DEFAULT_IDENTITY_NAME.to_string());
    let environment =
        std::env::var("INFISICAL_ENVIRONMENT").unwrap_or_else(|_| DEFAULT_ENVIRONMENT.to_string());
    let env_file: PathBuf = std::env::var("MOKOSH_ENV_FILE")
        .unwrap_or_else(|_| DEFAULT_ENV_FILE.to_string())
        .into();

    let config = DevBootstrapConfig {
        url: url.clone(),
        env_file: env_file.clone(),
        input: BootstrapInput {
            admin_email,
            admin_password,
            admin_first_name,
            admin_last_name,
            project_name,
            project_description: Some("Mokosh Server secrets".to_string()),
            identity_name,
            client_secret_description: Some("Mokosh bootstrap".to_string()),
            environment_slug: Some(environment),
        },
    };

    let output = run_dev_bootstrap(config).await?;

    println!("Bootstrap complete.");
    println!("  Project ID:     {}", output.project_id);
    println!("  Project slug:   {}", output.project_slug);
    println!("  Environment:    {}", output.environment);
    println!("  Identity ID:    {}", output.identity_id);
    println!("  Client ID:      {}", output.client_id);
    println!("  Env file:       {}", env_file.display());
    println!();
    println!("Wrote INFISICAL_PROJECT_ID, INFISICAL_CLIENT_ID, INFISICAL_CLIENT_SECRET,");
    println!("INFISICAL_ENVIRONMENT, INFISICAL_ADMIN_EMAIL, INFISICAL_ADMIN_PASSWORD.");
    println!("Restart Mokosh services so they pick up the new credentials.");
    Ok(())
}

// --- qa-seed / qa-teardown (PMS-331) -------------------------------------

/// Drive the on-demand QA walkthrough dataset seed / teardown. `subcommand` is
/// `"qa-seed"` or `"qa-teardown"`. The target tenant is taken from
/// `--tenant <uuid>` (or the `MOKOSH_QA_TENANT_ID` env var) and is
/// cross-checked against the `is_qa` marker by the seed itself, which refuses
/// (zero writes) for any tenant not explicitly marked QA, production included.
async fn run_qa(subcommand: &str, args: &[String]) -> anyhow::Result<()> {
    use crate::db::Database;

    let tenant_id = parse_tenant_arg(args)?;

    // The QA seed is a trusted admin tool. Connect the privileged
    // `DATABASE_URL` as both pools so per-tenant RLS does not bite while the
    // seed writes through the tenant-scoped service layer.
    let database_url = require_env("DATABASE_URL")?;
    let db = Database::new(&database_url, &database_url)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to database: {e}"))?;

    let report = match subcommand {
        "qa-seed" => crate::modules::seed::qa_seed(&db, tenant_id).await,
        "qa-teardown" => crate::modules::seed::qa_teardown(&db, tenant_id).await,
        other => unreachable!("unexpected qa subcommand {other}"),
    }
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("{subcommand} complete for tenant {tenant_id}.");
    println!("  {report}");
    Ok(())
}

// --- showcase-seed / showcase-refresh / showcase-teardown (PMS-620) ------

/// Drive the on-demand showcase demo dataset. `subcommand` is one of
/// `"showcase-seed"`, `"showcase-refresh"`, `"showcase-teardown"`. The target
/// tenant is taken from `--tenant <uuid>` (or the `MOKOSH_SHOWCASE_TENANT_ID`
/// env var) and is cross-checked against the `is_showcase` marker by the seed
/// itself, which refuses (zero writes) for any tenant not explicitly marked
/// showcase, production included.
async fn run_showcase(subcommand: &str, args: &[String]) -> anyhow::Result<()> {
    use crate::db::Database;

    let tenant_id = parse_tenant_arg_env(args, "MOKOSH_SHOWCASE_TENANT_ID", "showcase")?;

    // The showcase seed is a trusted admin tool. Connect the privileged
    // `DATABASE_URL` as both pools so per-tenant RLS does not bite while the
    // seed writes through the tenant-scoped service layer.
    let database_url = require_env("DATABASE_URL")?;
    let db = Database::new(&database_url, &database_url)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to database: {e}"))?;

    let report = match subcommand {
        "showcase-seed" => crate::modules::seed::showcase_seed(&db, tenant_id).await,
        "showcase-refresh" => crate::modules::seed::showcase_refresh(&db, tenant_id).await,
        "showcase-teardown" => crate::modules::seed::showcase_teardown(&db, tenant_id).await,
        other => unreachable!("unexpected showcase subcommand {other}"),
    }
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("{subcommand} complete for tenant {tenant_id}.");
    println!("  {report}");
    Ok(())
}

/// Resolve the QA tenant id from `--tenant <uuid>`, falling back to the
/// `MOKOSH_QA_TENANT_ID` env var. Errors if neither is present or the value is
/// not a UUID.
fn parse_tenant_arg(args: &[String]) -> anyhow::Result<uuid::Uuid> {
    parse_tenant_arg_env(args, "MOKOSH_QA_TENANT_ID", "QA")
}

/// Resolve a tenant id from `--tenant <uuid>`, falling back to the named env
/// var. `label` names the dataset for the error message. Errors if neither is
/// present or the value is not a UUID.
fn parse_tenant_arg_env(args: &[String], env_key: &str, label: &str) -> anyhow::Result<uuid::Uuid> {
    let raw = args
        .iter()
        .position(|a| a == "--tenant")
        .and_then(|i| args.get(i + 1).cloned())
        .or_else(|| std::env::var(env_key).ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the {label} tenant id is required: pass --tenant <uuid> or set {env_key}"
            )
        })?;
    uuid::Uuid::parse_str(raw.trim())
        .map_err(|_| anyhow::anyhow!("invalid tenant id '{raw}': expected a UUID"))
}

fn require_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| {
        anyhow::anyhow!(
            "{} is not set. Put it in .env.infisical or export it before running.",
            key
        )
    })
}
