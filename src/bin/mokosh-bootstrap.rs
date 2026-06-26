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
        // `mokosh-bootstrap clients register` registers a new OAuth/OIDC
        // client in mokosh_auth.oauth_clients. The form in argv is
        // intentional: future client subcommands (`list`, `disable`,
        // `rotate-secret`) slot in alongside without churn.
        Some("clients") => match args.get(2).map(String::as_str) {
            Some("register") => match run_clients_register().await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {:#}", e);
                    ExitCode::FAILURE
                }
            },
            Some(other) => {
                eprintln!("error: unknown clients subcommand '{}'\n", other);
                print_help();
                ExitCode::FAILURE
            }
            None => {
                eprintln!("error: `clients` requires a subcommand\n");
                print_help();
                ExitCode::FAILURE
            }
        },
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
    clients register       Register a new OAuth/OIDC client in mokosh_auth.
    qa-seed                Seed the QA walkthrough dataset into a QA-marked tenant (PMS-331).
    qa-teardown            Remove the QA walkthrough dataset from a QA-marked tenant.
    --version, -V          Print version information and exit.

ENVIRONMENT (qa-seed / qa-teardown):
    DATABASE_URL           (required) Privileged Postgres URL.
    --tenant <uuid>        (required) Target tenant id. May instead be given as MOKOSH_QA_TENANT_ID.
                           The tenant MUST be marked QA first (fail closed, refuses production):
                             UPDATE tenants SET settings = jsonb_set(COALESCE(settings,'{{}}'::jsonb),
                               '{{is_qa}}', 'true'::jsonb, true) WHERE id = '<qa-tenant-id>';

ENVIRONMENT (clients register):
    DATABASE_URL                     (required) Postgres URL for mokosh_auth.
    MOKOSH_CLIENT_NAME               (required) Human-readable client name.
    MOKOSH_CLIENT_TYPE               public | confidential (default: confidential).
    MOKOSH_CLIENT_REDIRECT_URIS      (required) Comma-separated redirect URIs.
    MOKOSH_CLIENT_POST_LOGOUT_URIS   Comma-separated post-logout URIs.
    MOKOSH_CLIENT_BACKCHANNEL_URI    Optional back-channel logout URL.
    MOKOSH_CLIENT_LIFECYCLE_URI      Optional lifecycle event URL.
    MOKOSH_CLIENT_SCOPES             Space-separated scopes (default: openid email offline_access).
    MOKOSH_CLIENT_GRANT_TYPES        Space-separated grants (default: authorization_code refresh_token).
    MOKOSH_CLIENT_AUTH_METHOD        none | client_secret_basic | client_secret_post
                                     (default: client_secret_basic for confidential, none for public).
    MOKOSH_CLIENT_AUDIENCE           (required) Audience for issued access tokens.
    MOKOSH_CLIENT_TENANT_ID          Optional UUID; omit for platform-wide client.
    MOKOSH_CLIENT_DESCRIPTION        Optional short blurb shown by the Bunyip app launcher.
    MOKOSH_CLIENT_ICON_URL           Optional icon URL shown by the Bunyip app launcher.
    MOKOSH_CLIENT_ACCESS_TOKEN_TTL   Access-token lifetime in seconds (60-3600, default 600).

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

// --- clients register ----------------------------------------------------

async fn run_clients_register() -> anyhow::Result<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::RngCore;
    use sqlx::postgres::PgPoolOptions;

    let database_url = require_env("DATABASE_URL")?;
    let name = require_env("MOKOSH_CLIENT_NAME")?;
    let client_type =
        std::env::var("MOKOSH_CLIENT_TYPE").unwrap_or_else(|_| "confidential".to_string());
    if !matches!(client_type.as_str(), "public" | "confidential") {
        anyhow::bail!("MOKOSH_CLIENT_TYPE must be 'public' or 'confidential'");
    }

    let redirect_uris = parse_csv(&require_env("MOKOSH_CLIENT_REDIRECT_URIS")?);
    if redirect_uris.is_empty() {
        anyhow::bail!("MOKOSH_CLIENT_REDIRECT_URIS must list at least one URI");
    }
    for u in &redirect_uris {
        url::Url::parse(u).map_err(|e| anyhow::anyhow!("invalid redirect URI `{}`: {}", u, e))?;
    }

    let post_logout_uris = std::env::var("MOKOSH_CLIENT_POST_LOGOUT_URIS")
        .map(|s| parse_csv(&s))
        .unwrap_or_default();
    let backchannel = std::env::var("MOKOSH_CLIENT_BACKCHANNEL_URI")
        .ok()
        .filter(|s| !s.is_empty());
    let lifecycle = std::env::var("MOKOSH_CLIENT_LIFECYCLE_URI")
        .ok()
        .filter(|s| !s.is_empty());

    let scopes = std::env::var("MOKOSH_CLIENT_SCOPES")
        .unwrap_or_else(|_| "openid email offline_access".to_string());
    let scope_vec: Vec<String> = scopes.split_whitespace().map(String::from).collect();
    let grants = std::env::var("MOKOSH_CLIENT_GRANT_TYPES")
        .unwrap_or_else(|_| "authorization_code refresh_token".to_string());
    let grant_vec: Vec<String> = grants.split_whitespace().map(String::from).collect();

    let auth_method =
        std::env::var("MOKOSH_CLIENT_AUTH_METHOD").unwrap_or_else(|_| match client_type.as_str() {
            "public" => "none".to_string(),
            _ => "client_secret_basic".to_string(),
        });
    if !matches!(
        auth_method.as_str(),
        "none" | "client_secret_basic" | "client_secret_post"
    ) {
        anyhow::bail!(
            "MOKOSH_CLIENT_AUTH_METHOD must be one of: none, client_secret_basic, client_secret_post"
        );
    }
    // Public clients must use `none`; confidential must use a secret-based method.
    match (client_type.as_str(), auth_method.as_str()) {
        ("public", "none") => {}
        ("public", _) => anyhow::bail!("public clients must use auth_method=none"),
        ("confidential", "none") => {
            anyhow::bail!("confidential clients must use a secret-based auth_method")
        }
        _ => {}
    }

    let audience = require_env("MOKOSH_CLIENT_AUDIENCE")?;
    let description = std::env::var("MOKOSH_CLIENT_DESCRIPTION")
        .ok()
        .filter(|s| !s.is_empty());
    let icon_url = std::env::var("MOKOSH_CLIENT_ICON_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let access_token_ttl: Option<i32> = match std::env::var("MOKOSH_CLIENT_ACCESS_TOKEN_TTL") {
        Ok(s) if !s.is_empty() => Some(
            s.parse()
                .map_err(|e| anyhow::anyhow!("MOKOSH_CLIENT_ACCESS_TOKEN_TTL: {}", e))?,
        ),
        _ => None,
    };
    let tenant_id = std::env::var("MOKOSH_CLIENT_TENANT_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<uuid::Uuid>())
        .transpose()
        .map_err(|e| anyhow::anyhow!("MOKOSH_CLIENT_TENANT_ID: {}", e))?;

    // Generate identifiers + (for confidential) a secret.
    let client_id = uuid::Uuid::new_v4();
    let (raw_secret, secret_hash) = if client_type == "confidential" {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let raw = URL_SAFE_NO_PAD.encode(bytes);
        let hash = mokosh_auth::crypto::hash_password(&raw)
            .map_err(|e| anyhow::anyhow!("hash_password: {}", e))?;
        (Some(raw), Some(hash))
    } else {
        (None, None)
    };

    // Connect and INSERT.
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await?;

    // `COALESCE($16, access_token_ttl_seconds)` keeps the DB
    // default (600) intact when the env var is unset, so the new
    // column does not silently widen the lifetime on omitted calls.
    sqlx::query(
        "INSERT INTO mokosh_auth.oauth_clients
            (client_id, tenant_id, client_secret_hash, client_type, name,
             redirect_uris, post_logout_redirect_uris, backchannel_logout_uri,
             lifecycle_event_uri, allowed_scopes, allowed_grant_types,
             token_endpoint_auth_method, audience, description, icon_url,
             access_token_ttl_seconds)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                 COALESCE($16, 600))",
    )
    .bind(client_id)
    .bind(tenant_id)
    .bind(&secret_hash)
    .bind(&client_type)
    .bind(&name)
    .bind(&redirect_uris)
    .bind(&post_logout_uris)
    .bind(&backchannel)
    .bind(&lifecycle)
    .bind(&scope_vec)
    .bind(&grant_vec)
    .bind(&auth_method)
    .bind(&audience)
    .bind(&description)
    .bind(&icon_url)
    .bind(access_token_ttl)
    .execute(&pool)
    .await?;

    println!("Client registered.");
    println!("  client_id:      {}", client_id);
    println!("  name:           {}", name);
    println!("  type:           {}", client_type);
    println!("  redirect_uris:  {}", redirect_uris.join(", "));
    println!("  scopes:         {}", scope_vec.join(" "));
    println!("  audience:       {}", audience);
    if let Some(secret) = raw_secret {
        println!();
        println!("  client_secret:  {}", secret);
        println!("  ^ Save this now. The hash is in the database; the raw value");
        println!("    will not be shown again.");
    }
    Ok(())
}

fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}
