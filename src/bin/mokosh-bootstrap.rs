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
    --version, -V          Print version information and exit.

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

fn require_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| {
        anyhow::anyhow!(
            "{} is not set. Put it in .env.infisical or export it before running.",
            key
        )
    })
}
