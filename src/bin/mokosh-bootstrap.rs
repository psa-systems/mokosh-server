//! `mokosh-bootstrap` CLI.
//!
//! Currently exposes a single subcommand, `bootstrap-infisical`, which drives
//! the first-run setup of a fresh Infisical instance and writes the resulting
//! Universal Auth credentials into `.env` so the dev stack picks them up on
//! the next restart.
//!
//! The CLI reads everything it needs from environment variables (typically
//! sourced from a gitignored `.env.infisical` file by the `just
//! infisical-bootstrap` recipe). This avoids putting an admin password on
//! the shell command line where it would land in shell history.

use std::path::PathBuf;
use std::process::ExitCode;

use mokosh_server::infisical::{run_dev_bootstrap, BootstrapInput, DevBootstrapConfig};
use mokosh_server::version::VersionInfo;

const DEFAULT_URL: &str = "http://localhost:28002";
const DEFAULT_PROJECT_NAME: &str = "mokosh";
const DEFAULT_IDENTITY_NAME: &str = "mokosh-machine";
const DEFAULT_ENVIRONMENT: &str = "dev";
const DEFAULT_ENV_FILE: &str = ".env";
const DEFAULT_ADMIN_FIRST_NAME: &str = "Mokosh";
const DEFAULT_ADMIN_LAST_NAME: &str = "Admin";

#[tokio::main]
async fn main() -> ExitCode {
    // Load .env / .env.infisical so values can be read via env vars without
    // forcing the operator to `export` them in their shell.
    let _ = dotenvy::from_filename(".env.infisical");
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(String::as_str);

    match subcommand {
        Some("--version") | Some("-V") => {
            println!("{}", VersionInfo::current().banner());
            ExitCode::SUCCESS
        }
        Some("bootstrap-infisical") => {
            tracing::info!("Starting {}", VersionInfo::current().banner());
            match run_bootstrap_infisical().await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {:#}", e);
                    ExitCode::FAILURE
                }
            }
        }
        // `mokosh-bootstrap qa-seed --tenant <uuid>` loads the QA walkthrough
        // dataset (PMS-331) into a tenant explicitly marked QA. `qa-teardown`
        // removes it. Both fail closed against any non-QA / production tenant.
        Some("qa-seed") => match run_qa("qa-seed", &args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {:#}", e);
                ExitCode::FAILURE
            }
        },
        Some("qa-teardown") => match run_qa("qa-teardown", &args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {:#}", e);
                ExitCode::FAILURE
            }
        },
        // PMS-729: seed a small portal-login fixture set (three tenants +
        // one portal contact per tenant, all sharing PORTAL_DEV_PASSWORD)
        // so a developer can exercise the client-portal login flow at
        // `http://{slug}.client.localhost:4301/portal/login`. Fail-closes
        // outside dev/test/development ENVIRONMENT and is idempotent.
        Some("dev-seed-portal") => match run_dev_seed_portal().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {:#}", e);
                ExitCode::FAILURE
            }
        },
        // PMS-602: normalize existing free-text company industries to the
        // canonical set across all tenants. Re-runnable / no-op-safe.
        Some("normalize-company-industries") => match run_normalize_industries().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {:#}", e);
                ExitCode::FAILURE
            }
        },
        Some("--help") | Some("-h") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown subcommand '{}'\n", other);
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    eprintln!(
        "mokosh-bootstrap {version} ({hash}) - Mokosh Server bootstrap utility
Built {date}.

USAGE:
    mokosh-bootstrap <SUBCOMMAND>

SUBCOMMANDS:
    bootstrap-infisical    First-run setup of a fresh Infisical instance.
    qa-seed                Seed the QA walkthrough dataset into a QA-marked tenant (PMS-331).
    qa-teardown            Remove the QA walkthrough dataset from a QA-marked tenant.
    dev-seed-portal        Seed portal-login fixture tenants + contacts (PMS-729, dev only).
    normalize-company-industries
                           Normalize existing free-text company industries to the canonical
                           set across all tenants (PMS-602). Re-runnable; reports unmapped values.
    --version, -V          Print version information and exit.

ENVIRONMENT (qa-seed / qa-teardown):
    DATABASE_URL           (required) Privileged Postgres URL.
    --tenant <uuid>        (required) Target tenant id. May instead be given as MOKOSH_QA_TENANT_ID.
                           The tenant MUST be marked QA first (fail closed, refuses production):
                             UPDATE tenants SET settings = jsonb_set(COALESCE(settings,'{{}}'::jsonb),
                               '{{is_qa}}', 'true'::jsonb, true) WHERE id = '<qa-tenant-id>';

ENVIRONMENT (bootstrap-infisical):
    INFISICAL_ADMIN_EMAIL          (required) Admin user email.
    INFISICAL_ADMIN_PASSWORD       (required) Admin user password (>= 12 chars).
    INFISICAL_ADMIN_FIRST_NAME     Admin first name (default: {first}).
    INFISICAL_ADMIN_LAST_NAME      Admin last name  (default: {last}).
    INFISICAL_URL                  Bootstrap target URL (default: {url}).
    INFISICAL_PROJECT_NAME         Project to create (default: {project}).
    INFISICAL_IDENTITY_NAME        Machine identity (default: {identity}).
    INFISICAL_ENVIRONMENT          Environment slug (default: {env}).
    MOKOSH_ENV_FILE                .env path to update (default: {file}).
",
        first = DEFAULT_ADMIN_FIRST_NAME,
        last = DEFAULT_ADMIN_LAST_NAME,
        url = DEFAULT_URL,
        project = DEFAULT_PROJECT_NAME,
        identity = DEFAULT_IDENTITY_NAME,
        env = DEFAULT_ENVIRONMENT,
        file = DEFAULT_ENV_FILE,
        version = mokosh_server::version::GIT_DESCRIBE,
        hash = mokosh_server::version::GIT_HASH,
        date = mokosh_server::version::BUILD_DATE,
    );
}

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
    use mokosh_server::db::Database;

    let tenant_id = parse_tenant_arg(args)?;

    // The QA seed is a trusted admin tool. Connect the privileged
    // `DATABASE_URL` as both pools so per-tenant RLS does not bite while the
    // seed writes through the tenant-scoped service layer.
    let database_url = require_env("DATABASE_URL")?;
    let db = Database::new(&database_url, &database_url)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to database: {e}"))?;

    let report = match subcommand {
        "qa-seed" => mokosh_server::modules::seed::qa_seed(&db, tenant_id).await,
        "qa-teardown" => mokosh_server::modules::seed::qa_teardown(&db, tenant_id).await,
        other => unreachable!("unexpected qa subcommand {other}"),
    }
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("{subcommand} complete for tenant {tenant_id}.");
    println!("  {report}");
    Ok(())
}

/// PMS-729: seed the client-portal login fixture set (three tenants +
/// one portal contact each, sharing a fixed dev password). The seeder
/// itself refuses to run outside `ENVIRONMENT=development|dev|test`, so
/// no additional guard is needed here.
async fn run_dev_seed_portal() -> anyhow::Result<()> {
    use mokosh_server::db::Database;

    let database_url = require_env("DATABASE_URL")?;
    let db = Database::new(&database_url, &database_url)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to database: {e}"))?;

    // Run migrations before seeding so a fresh dev DB (no `tenants` table
    // yet) still succeeds. Cheap on a warm DB (sqlx no-ops when the
    // checksum ledger says every migration already ran) and covers the
    // "just ran `just dev` once but never let the server complete boot"
    // case that would otherwise 42P01 on the tenants insert.
    db.run_migrations()
        .await
        .map_err(|e| anyhow::anyhow!("run migrations before seeding: {e}"))?;

    // The seeder writes tenants + companies + contacts directly and does
    // not need per-tenant RLS to fire, so it uses the migrator pool.
    // Bubble the anyhow chain verbatim so `error: {:#}` in main() renders
    // every layer (sqlx error, then `seed tenant 'X'`, then the top).
    let report = mokosh_server::modules::seed::portal_dev_seed(db.migrator_pool()).await?;

    print!("{report}");
    Ok(())
}

/// PMS-602: rewrite existing free-text `companies.industry` values to the
/// canonical set across every tenant. Cross-tenant operator task, so it
/// connects the privileged `DATABASE_URL` (BYPASSRLS) as both pools like the QA
/// tooling does.
async fn run_normalize_industries() -> anyhow::Result<()> {
    use mokosh_server::db::Database;

    let database_url = require_env("DATABASE_URL")?;
    let db = Database::new(&database_url, &database_url)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to database: {e}"))?;

    let report = mokosh_server::modules::contacts::normalize_company_industries(&db)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("{report}");
    Ok(())
}

/// Resolve the QA tenant id from `--tenant <uuid>`, falling back to the
/// `MOKOSH_QA_TENANT_ID` env var. Errors if neither is present or the value is
/// not a UUID.
fn parse_tenant_arg(args: &[String]) -> anyhow::Result<uuid::Uuid> {
    let raw = args
        .iter()
        .position(|a| a == "--tenant")
        .and_then(|i| args.get(i + 1).cloned())
        .or_else(|| std::env::var("MOKOSH_QA_TENANT_ID").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the QA tenant id is required: pass --tenant <uuid> or set MOKOSH_QA_TENANT_ID"
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
