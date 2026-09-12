//! Mokosh Server - API server entrypoint

use mokosh_server::config::{self, registry as keys, ConfigKey};
use mokosh_server::utils::deployment::{
    DeploymentMode, EnablementSource, ProviderKind, ProviderOverrides,
};
use mokosh_server::{api::create_api_router, version::VersionInfo, Database};
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Application configuration loaded from environment
#[derive(Clone, Debug)]
pub struct AppConfig {
    /// Privileged (`mokosh_migrator`, BYPASSRLS) connection string. Runs
    /// migrations, bootstrap, the cross-tenant workers and the
    /// explicitly-justified pre-auth / cross-tenant paths.
    pub database_url: String,
    /// Request-serving (`mokosh_app`, NOSUPERUSER NOBYPASSRLS) connection
    /// string (PMS-285). Falls back to `database_url` when unset, which
    /// preserves the pre-split single-role behaviour (RLS does not bite
    /// because the single role bypasses it).
    pub app_database_url: String,
    pub jwt_secret: String,
    pub host: String,
    pub port: u16,
    pub environment: String,
    pub base_url: String,
    pub run_migrations: bool,
    pub encryption_key: String,
    /// Browser-visible origin of the client that talks to this API: the
    /// CORS_ORIGIN default and the base for emailed reset / invite links.
    ///
    /// On both deployed environments this is the APEX, not the mokosh-apps
    /// SPA: bunyip-web hosts the login UI there, so this is the apex
    /// byte-for-byte
    /// (staging `https://a8n.systems`, prod `https://psa.systems`). Do not
    /// reuse it as a base for links to mokosh-apps pages - use
    /// [`AppConfig::spa_base_url`].
    pub client_origin: String,
    /// MAPPS-425: browser origin of the mokosh-apps SPA
    /// (`https://msp.a8n.systems`, `https://msp.psa.systems`), the base for
    /// emailed links to pages that exist ONLY in mokosh-apps.
    ///
    /// Separate from [`AppConfig::client_origin`] and from `BASE_URL`, both of
    /// which point at the apex on purpose because bunyip-web owns login and
    /// `/reset-password` there. The request-form link is the
    /// first emailed link whose page bunyip does NOT have, and pointing it at
    /// the apex sent every client to bunyip's 404.
    ///
    /// Defaults to `client_origin`, so a single-origin dev stack (where the
    /// SPA and the shell are the same host) needs no new configuration.
    pub spa_base_url: String,
    /// PMS-748: address a client can report an unwanted request-form email to.
    ///
    /// Per deployment rather than per tenant, because the whole point of an
    /// abuse channel is that it does NOT reach the sender. `None` when unset,
    /// and the email then carries no report-abuse line at all: a link that
    /// goes nowhere, or to a noreply address, is worse than no link.
    pub abuse_contact_email: Option<String>,
    /// MAPPS-429: this deployment's own public API base
    /// (`https://api.msp.a8n.systems`), used to make the tenant logo absolute
    /// for a mail client, which cannot resolve a relative `src`.
    ///
    /// Deliberately NOT derived from `base_url` or `spa_base_url`: on every
    /// deployed environment those are the apex and the SPA, and the logo is
    /// served by the API on a third host. `None` omits the logo from the email
    /// rather than emitting a broken image.
    pub public_api_base_url: Option<String>,
    /// All origins permitted to make credentialed CORS requests against
    /// the API. Defaults to `[client_origin]` if `CORS_ORIGIN` is unset.
    /// Set via the `CORS_ORIGIN` env var as a comma-separated list (e.g.
    /// staging `https://msp.a8n.systems,https://a8n.systems`, prod
    /// `https://msp.psa.systems,https://psa.systems`).
    pub cors_origins: Vec<String>,
    /// PMS-591: shared secret Bunyip signs its `account_deleted` webhook
    /// payload with. Bunyip signs every outbound webhook with ONE service-wide
    /// HMAC-SHA256 secret (see `bunyip crates/bunyip-domain/src/services/webhook.rs`
    /// `WebhookService::new(signing_secret)`), NOT a per-app value on any
    /// `applications` row - the model has no `webhook_secret` column. Both
    /// sides must hold the same value: bunyip reads it from
    /// `BUNYIP_WEBHOOK_SIGNING_SECRET` (BUNYIP-332), mokosh reads it from
    /// `BUNYIP_WEBHOOK_SECRET`.
    pub bunyip_webhook_secret: String,
    /// PMS-657: path to the IP2Location LITE `.BIN` DB used to resolve a login's
    /// client IP to a country for login-location alerts. `None` when unset: the
    /// alert feature is disabled (the server still boots normally).
    pub ip2location_db_path: Option<String>,
    /// BUNYIP-475: path to the IP2Proxy PX `.BIN` used for advisory ASN / VPN
    /// enrichment of a client IP (the shared dunite-ipenrich signal). `None` when
    /// unset: the admin enrichment lookup reports nothing and the server boots
    /// normally.
    pub ip2proxy_db_path: Option<String>,
    /// PMS-658: opt-in switch for the suspicious-login notify-and-approve gate
    /// (`LOGIN_APPROVAL_ENABLED`). Off by default.
    pub login_approval_enabled: bool,
    /// MAPPS-457: instance-wide hard cap on how many tenants a super-admin can
    /// create. Unset (or `<=0`) leaves creation uncapped, matching production
    /// today. Positive integer rejects further `create_tenant` calls with 409
    /// once `SELECT COUNT(*) FROM tenants` reaches the value.
    ///
    /// Set via `MOKOSH_MAX_TENANTS`. Bumped without a code change so an
    /// operator can raise the ceiling on the running instance and see the
    /// effect on the next create call (no restart needed for lowering /
    /// raising - re-read at each create request).
    pub max_tenants: Option<usize>,
    /// PMS-902 / PMS-904: whether this instance owns its platform identities
    /// (`self-hosted`, the default) or federates them to Bunyip SSO (`saas`).
    /// Read from `MOKOSH_DEPLOYMENT_MODE`; see [`DeploymentMode`].
    pub deployment_mode: DeploymentMode,
}

/// Dev-only fallback for `JWT_SECRET`. Accepted only in dev/test
/// environments; in any other environment its presence (or an unset
/// `JWT_SECRET`) is a fatal boot error (PMS-499).
const DEV_JWT_SECRET: &str = "development-secret-change-in-production";
/// Dev-only fallback for `ENCRYPTION_KEY`. Same production guard as
/// [`DEV_JWT_SECRET`] (PMS-499).
const DEV_ENCRYPTION_KEY: &str = "32-byte-key-for-dev-only-change!";
/// Dev-only fallback for `BUNYIP_WEBHOOK_SECRET` (PMS-591). Accepted only
/// in dev/test; production/staging must set a real value matching bunyip's
/// service-wide `WebhookService` signing secret (BUNYIP-332), or boot fails.
const DEV_BUNYIP_WEBHOOK_SECRET: &str = "development-bunyip-webhook-secret-change";

/// True for the environments that may use the hardcoded dev fallbacks.
/// Anything else (staging, production, or an unrecognized value) fails
/// safe: it must supply real secrets. Mirrors [`AppConfig::is_dev_or_test`]
/// but works on the raw env string before the struct is built.
fn env_allows_dev_secrets(environment: &str) -> bool {
    matches!(environment, "development" | "dev" | "test")
}

/// Minimum acceptable `JWT_SECRET` length outside dev/test. An HS256 key
/// shorter than the 32-byte SHA-256 output is below the algorithm's own
/// security margin (PMS-497).
const MIN_JWT_SECRET_LEN: usize = 32;

/// Outside dev/test, reject a `JWT_SECRET` below the HS256 32-byte security
/// margin. `resolve_secret` already rejected the unset / dev-default cases
/// (PMS-499); this adds the length floor (PMS-497).
fn check_jwt_secret_len(secret: &str, environment: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !env_allows_dev_secrets(environment) && secret.len() < MIN_JWT_SECRET_LEN {
        return Err(format!(
            "JWT_SECRET must be at least {MIN_JWT_SECRET_LEN} bytes in the '{environment}' \
             environment; only development/dev/test accept a shorter secret."
        )
        .into());
    }
    Ok(())
}

/// True when `s` is exactly 64 ASCII hex characters - the canonical
/// `ENCRYPTION_KEY` form (32 bytes, hex-encoded) required outside dev/test
/// (PMS-498). A raw 32-byte key is ambiguous and weaker to mistype, so it is
/// accepted only in dev/test.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One essential deployment-shape variable's boot-check contract.
///
/// Every field is a `&'static str` or a `fn` pointer because the set is closed
/// and known at compile time: five vars whose "wrong default" is silent-but-
/// consequential on a real deployment (`MOKOSH_DEPLOYMENT_MODE` selects the
/// hosting profile defaults per capability, `MOKOSH_APP_DATABASE_URL` decides
/// whether RLS bites at all, and the three URLs decide where emailed and
/// browser links land). See PMS-1160.
///
/// The reader is a `fn` rather than a `&'static ConfigKey` because
/// `MOKOSH_DEPLOYMENT_MODE` is deliberately NOT in the config-provider
/// registry: it selects which providers exist and so cannot itself be read
/// through one (see `src/config/guard.rs::ENTRY_POINTS`, which lists
/// `src/utils/deployment.rs` for exactly this reason). Every other requirement
/// here IS in the registry and its reader delegates to `config::get`.
struct DeploymentRequirement {
    /// The env var name as an operator writes it and as the failure message
    /// prints it.
    name: &'static str,
    /// Reads the current value of this variable. Returns `None` when the
    /// variable is unset OR when its value is a blank string (a
    /// forwarded-but-unset compose key arrives as `""`, PMS-836).
    reader: fn() -> Option<String>,
    /// One-sentence reason the operator gets in the failure message.
    purpose: &'static str,
    /// Closed set of legal values when the shape is enumerated; empty when the
    /// shape is a URL or other open-set value.
    options: &'static [&'static str],
    /// A shape example an operator can copy; the failure message names it so
    /// an operator can act without a second doc lookup.
    example: &'static str,
}

/// The five deployment-shape variables mokosh-server refuses to start without
/// outside dev/test (PMS-1160). The list is ORDERED by consequence: the first
/// one that fails at boot is the first one printed, so an operator who lands
/// on a fresh compose fills them in top-to-bottom.
///
/// This list is not the same as `.env.example`: `.env.example` shows every
/// variable the code reads, while this list is the closed subset whose
/// absence in a real deployment is silent-and-wrong rather than
/// silent-and-defaulted. Provision-time secrets (`MOKOSH_ADMIN_DATABASE_URL`,
/// `MOKOSH_MIGRATOR_PASSWORD`, `MOKOSH_APP_PASSWORD`) stay out of this list
/// because `db::provision::provision_roles` refuses them at exactly the
/// moment they are needed, which is the first boot on a database that has
/// never been provisioned.
const ESSENTIAL_DEPLOYMENT_REQUIREMENTS: &[DeploymentRequirement] = &[
    DeploymentRequirement {
        name: "MOKOSH_DEPLOYMENT_MODE",
        reader: mokosh_server::utils::deployment::raw_deployment_mode,
        purpose: "selects hosting-profile defaults for every capability \
                  (authentication, secrets, storage, email). Silently defaulting to \
                  self-hosted on the SaaS deployment on 2026-09-10 rejected every \
                  Bunyip bearer with 401.",
        options: &["self-hosted", "saas"],
        example: "MOKOSH_DEPLOYMENT_MODE=saas",
    },
    DeploymentRequirement {
        name: "MOKOSH_APP_DATABASE_URL",
        reader: || config::get(&keys::MOKOSH_APP_DATABASE_URL),
        purpose: "the NOBYPASSRLS request-serving pool connection string. Unset \
                  makes the request pool fall back to DATABASE_URL (BYPASSRLS \
                  mokosh_migrator), so every RLS tenant_isolation policy is inert \
                  and tenant isolation depends entirely on the service layer. \
                  PMS-1158 is the discovery of this state on production.",
        options: &[],
        example: "MOKOSH_APP_DATABASE_URL=postgres://mokosh_app:<pw>@<host>:5432/mokosh",
    },
    DeploymentRequirement {
        name: "BASE_URL",
        reader: || config::get(&keys::BASE_URL),
        purpose: "base of platform-owned email links (password reset, portal grant, \
                  invoice pay). An unset value falls to localhost and every emailed \
                  link lands nowhere.",
        options: &[],
        example: "BASE_URL=https://a8n.systems",
    },
    DeploymentRequirement {
        name: "CLIENT_ORIGIN",
        reader: || config::get(&keys::CLIENT_ORIGIN),
        purpose: "the browser-visible origin of the SPA host that talks to this API. \
                  Used as the CORS_ORIGIN default and the OAuth popup postMessage \
                  origin check. Silently defaulting to localhost lets the popup \
                  round-trip fail in a way that reads as a login bug.",
        options: &[],
        example: "CLIENT_ORIGIN=https://a8n.systems",
    },
    DeploymentRequirement {
        name: "SPA_BASE_URL",
        reader: || config::get(&keys::SPA_BASE_URL),
        purpose: "base for emailed links to pages served ONLY by mokosh-apps \
                  (request forms, portal set-password, invoice Pay Now). Falls back \
                  to CLIENT_ORIGIN, which on a deployed environment is the apex \
                  where bunyip serves - not mokosh-apps - so every one of these \
                  links lands on bunyip's 404.",
        options: &[],
        example: "SPA_BASE_URL=https://msp.a8n.systems",
    },
];

/// Refuse to start when any essential deployment-shape variable is unset
/// outside dev/test (PMS-1160). Runs after `AppConfig::from_env` returns so
/// the resolved `ENVIRONMENT` decides whether the check gates.
///
/// Collects every missing variable and returns one combined error, so an
/// operator who is missing three does not have to iterate three times. The
/// error names each missing variable, its purpose, its options (when the set
/// is closed) and an example an operator can copy verbatim.
fn check_deployment_requirements(environment: &str) -> Result<(), Box<dyn std::error::Error>> {
    if env_allows_dev_secrets(environment) {
        return Ok(());
    }

    let mut missing: Vec<String> = Vec::new();
    for req in ESSENTIAL_DEPLOYMENT_REQUIREMENTS {
        let value = (req.reader)().unwrap_or_default();
        if value.trim().is_empty() {
            missing.push(format_missing_requirement(req, environment));
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "boot refused: {} essential deployment-shape variable(s) unset in the \
             '{environment}' environment. Only development/dev/test accept unset \
             values here; every other environment must declare the shape.\n\n{}",
            missing.len(),
            missing.join("\n\n")
        )
        .into())
    }
}

/// One requirement's failure block. Named to match the shape `resolve_secret`
/// uses so operators reading two different startup errors see the same layout.
fn format_missing_requirement(req: &DeploymentRequirement, environment: &str) -> String {
    let options = if req.options.is_empty() {
        String::new()
    } else {
        format!("\n       Available options: {}", req.options.join(" | "))
    };
    format!(
        "FATAL: {name} is unset in the '{environment}' environment.\n       \
         Purpose: {purpose}{options}\n       Example: {example}",
        name = req.name,
        purpose = req.purpose,
        options = options,
        example = req.example,
    )
}

/// Resolve a secret, refusing the dev fallback outside dev/test.
/// In dev/test an unset value falls back to `dev_value`. In every other
/// environment an unset value - or one explicitly set to `dev_value` - is a
/// fatal boot error, consistent with the other fail-loud startup checks
/// (SMTP/migrations) (PMS-499).
///
/// PMS-982: the value comes from the configuration provider. The rule is
/// [`resolve_secret_value`], which takes the string, so the cases below are
/// tested without mutating process-global environment behind a held
/// generation.
fn resolve_secret(
    key: &ConfigKey,
    environment: &str,
    dev_value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    resolve_secret_value(key.name(), config::get(key), environment, dev_value)
}

/// The rule itself, over a value the caller already has.
fn resolve_secret_value(
    var_name: &str,
    value: Option<String>,
    environment: &str,
    dev_value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match value {
        Some(value) if !value.is_empty() => {
            if value == dev_value && !env_allows_dev_secrets(environment) {
                return Err(format!(
                    "{var_name} is set to the known dev fallback value, which is refused in the \
                     '{environment}' environment. Set a real secret (only development/dev/test \
                     accept the dev default)."
                )
                .into());
            }
            Ok(value)
        }
        _ => {
            if env_allows_dev_secrets(environment) {
                Ok(dev_value.to_string())
            } else {
                Err(format!(
                    "{var_name} is unset but required in the '{environment}' environment; the \
                     hardcoded dev fallback is only accepted in development/dev/test."
                )
                .into())
            }
        }
    }
}

impl AppConfig {
    /// PMS-982: every value below comes from the configuration provider, which
    /// `main` has already initialised. Each field's own emptiness, trimming and
    /// default rule is unchanged; only where the string comes from moved.
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let environment =
            config::get(&keys::ENVIRONMENT).unwrap_or_else(|| "development".to_string());

        // PMS-499: refuse the hardcoded dev fallbacks for the auth/crypto
        // secrets outside dev/test. Resolved before the struct is built so a
        // production/staging/unknown environment fails loud at boot rather than
        // silently serving with a publicly-known JWT_SECRET / ENCRYPTION_KEY.
        let jwt_secret = resolve_secret(&keys::JWT_SECRET, &environment, DEV_JWT_SECRET)?;
        check_jwt_secret_len(&jwt_secret, &environment)?;
        let encryption_key =
            resolve_secret(&keys::ENCRYPTION_KEY, &environment, DEV_ENCRYPTION_KEY)?;
        let client_origin = config::get(&keys::CLIENT_ORIGIN)
            .unwrap_or_else(|| "http://localhost:4301".to_string());
        // MAPPS-425: falls back to `client_origin` so a single-origin dev
        // stack is unaffected. Deployed environments MUST set it, because
        // there `CLIENT_ORIGIN` is the apex and the SPA is a subdomain.
        let spa_base_url = config::get(&keys::SPA_BASE_URL)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| client_origin.clone());
        // PMS-748: optional on purpose. An unset value removes the line rather
        // than defaulting to the SMTP from-address, which is a noreply on every
        // deployed environment and would send abuse reports into a black hole.
        let abuse_contact_email = config::get(&keys::ABUSE_CONTACT_EMAIL)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let public_api_base_url = config::get(&keys::PUBLIC_API_BASE_URL)
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty());
        // PMS-591: shared secret for the BUNYIP-211 `account_deleted` webhook.
        // Same fail-loud posture as the other secrets: dev/test may fall back to
        // a hardcoded value, staging/production refuse to boot without a real
        // secret. Matches bunyip-api's `BUNYIP_WEBHOOK_SIGNING_SECRET`
        // (BUNYIP-332); bunyip signs every outbound webhook with a single
        // service-wide secret, not a per-Application value.
        let bunyip_webhook_secret = resolve_secret(
            &keys::BUNYIP_WEBHOOK_SECRET,
            &environment,
            DEV_BUNYIP_WEBHOOK_SECRET,
        )?;

        // PMS-498: outside dev/test the at-rest AES-256-GCM key must be the
        // unambiguous 64-hex form. resolve_secret already refuses an unset var
        // or the dev sentinel here; this additionally rejects a raw-ASCII or
        // mistyped key so production/staging cannot boot on a weak at-rest key.
        if !env_allows_dev_secrets(&environment) && !is_hex64(&encryption_key) {
            return Err(format!(
                "ENCRYPTION_KEY must be a 64-character hex string in the '{environment}' \
                 environment (32 bytes, hex-encoded); only development/dev/test accept a raw \
                 32-byte key."
            )
            .into());
        }

        Ok(Self {
            database_url: config::get(&keys::DATABASE_URL).unwrap_or_else(|| {
                "postgres://postgres:postgres@localhost:5432/mokosh".to_string()
            }),
            // PMS-285: the request-serving role. Default to DATABASE_URL so a
            // dev box without the split still boots (RLS stays inert until the
            // app role is a NOBYPASSRLS one).
            app_database_url: config::get(&keys::MOKOSH_APP_DATABASE_URL)
                .or_else(|| config::get(&keys::DATABASE_URL))
                .unwrap_or_else(|| {
                    "postgres://postgres:postgres@localhost:5432/mokosh".to_string()
                }),
            jwt_secret,
            host: config::get(&keys::HOST).unwrap_or_else(|| "0.0.0.0".to_string()),
            port: config::get(&keys::PORT)
                .unwrap_or_else(|| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            environment,
            base_url: config::get(&keys::BASE_URL)
                .unwrap_or_else(|| "http://localhost:8080".to_string()),
            run_migrations: config::get(&keys::RUN_MIGRATIONS)
                .unwrap_or_else(|| "true".to_string())
                .parse()
                .unwrap_or(true),
            encryption_key,
            client_origin: client_origin.clone(),
            spa_base_url,
            abuse_contact_email,
            public_api_base_url,
            cors_origins: config::get(&keys::CORS_ORIGIN)
                .map(|raw| {
                    raw.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| vec![client_origin.clone()]),
            bunyip_webhook_secret,
            // PMS-657: optional IP2Location DB path for login-location alerts.
            ip2location_db_path: config::get(&keys::IP2LOCATION_DB_PATH)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            // BUNYIP-475: optional IP2Proxy PX DB path for ASN / VPN enrichment.
            ip2proxy_db_path: config::get(&keys::IP2PROXY_DB_PATH)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            // PMS-658 / PMS-983: opt-in switch for the suspicious-login
            // notify-and-approve gate. Default false because it can withhold
            // a login; enable per deployment for a staged rollout. Read
            // through `config::flags::LOGIN_APPROVAL_ENABLED` so the parse
            // rule and the default live with the flag rather than here.
            login_approval_enabled: config::flags::LOGIN_APPROVAL_ENABLED.read(),
            // MAPPS-457: optional cap parsed from MOKOSH_MAX_TENANTS. Empty,
            // unset, unparseable, or non-positive -> None (uncapped). Positive
            // usize -> Some(N). The value is threaded into `TenantService` via
            // its builder so the service layer probes `COUNT(*)` before
            // insert.
            max_tenants: config::get(&keys::MOKOSH_MAX_TENANTS)
                .and_then(|raw| raw.trim().parse::<usize>().ok())
                .filter(|n| *n > 0),
            // PMS-902: self-hosted (default) or saas. Unset and unrecognised
            // both resolve to self-hosted, so a typo cannot silently stop a
            // self-hosted deployment's account email.
            deployment_mode: DeploymentMode::from_env(),
        })
    }

    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }

    /// Dev/test environments run over plain HTTP, where browsers drop
    /// `Secure` cookies. Only these opt out of secure cookies; every other
    /// environment (staging, production, or any unrecognized value) defaults
    /// to secure, so a misconfigured `ENVIRONMENT` fails safe.
    pub fn is_dev_or_test(&self) -> bool {
        matches!(self.environment.as_str(), "development" | "dev" | "test")
    }

    // PMS-262: single-tenant mode removed. Multi-tenant is the only mode.
    pub fn is_multi_tenant(&self) -> bool {
        true
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // PMS-494: operator subcommands fold into this binary. When argv's first
    // token selects one (`mokosh-server bootstrap-infisical|clients|qa-seed|
    // qa-teardown`), run that one-shot task and exit instead of starting the
    // long-running HTTP server. The server path continues below otherwise.
    let args: Vec<String> = std::env::args().collect();
    if args
        .get(1)
        .map(String::as_str)
        .is_some_and(mokosh_server::cli::is_subcommand)
    {
        return run_cli(&args).await;
    }

    // PMS-504 (M14): do not hardcode debug logging in every environment.
    // Honor RUST_LOG (the dev stack sets `info,mokosh_server=debug`) and fall
    // back to `info` when it is unset so production runs at info, not debug.
    // This also stops tower_http from logging request URIs (query strings can
    // carry OAuth `code`/`state`) at info by default (PMS-504 L13).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Starting {}", VersionInfo::current().banner());

    tracing::info!("Running in multi-tenant mode");

    // The env file has to land before ANYTHING reads a variable: the hosting
    // profile below chooses the configuration provider, and that provider then
    // resolves every declared key out of this process's environment.
    dotenvy::dotenv().ok();

    // PMS-1011: the same variable, read strictly, because this answer chooses
    // providers rather than gating mail. Read here so an unrecognised mode
    // ends startup before the database is touched, with a message naming the
    // legal values, instead of surfacing from whichever provider resolved
    // first. `config.deployment_mode` keeps the lenient reading for mail.
    let hosting_profile = DeploymentMode::from_env_for_providers()?;

    // PMS-982: pick the configuration provider and resolve the first
    // generation, before `AppConfig` or any feature asks for a value. An
    // unrecognised CONFIG_BACKEND ends startup here naming the legal values,
    // rather than silently serving from the default.
    let config_selection =
        config::init_from_env(hosting_profile.default_provider_for(ProviderKind::Configuration)?)?;

    let config = AppConfig::from_env().expect("Failed to load configuration");

    // PMS-1160: refuse to start when an essential deployment-shape variable
    // is unset outside dev/test. Two incidents in 48 hours came from this
    // class: MOKOSH_DEPLOYMENT_MODE unset (staging, 2026-09-10) rejected
    // every Bunyip bearer, and MOKOSH_APP_DATABASE_URL unset (both
    // deployments, 2026-09-11) leaves the request pool falling back to the
    // BYPASSRLS migrator role so every RLS policy is inert. Runs after
    // AppConfig::from_env so ENVIRONMENT decides whether the check gates.
    check_deployment_requirements(&config.environment)?;

    // PMS-489: self-provision the split DB roles (mokosh_migrator / mokosh_app)
    // from MOKOSH_ADMIN_DATABASE_URL on first boot, before connecting the
    // request pools. Skipped entirely when the migrator role already logs in,
    // so prod can drop the admin credentials after the first start. Supersedes
    // scripts/pg-init.sh and the removed `mokosh-bootstrap provision-roles`
    // step - one mechanism, identical in dev and prod, env-driven.
    mokosh_server::db::provision::provision_roles(&config.database_url).await?;

    let db = Database::new(&config.app_database_url, &config.database_url).await?;

    // A migration failure is fatal: exit non-zero rather than serve a
    // half-migrated database (PMS-286). Warn-and-continue here once let a
    // failed verification migration (040) boot a server that never became
    // healthy - the container went unhealthy and Traefik dropped its router,
    // so every request 404'd with no hint at the real cause. Fail loud at boot,
    // consistent with the other startup checks (SMTP/ENCRYPTION_KEY/CORS
    // all hard-fail). `RUN_MIGRATIONS=false` still skips the step entirely for
    // operators who manage migrations out of band.
    if config.run_migrations {
        if let Err(e) = db.run_migrations().await {
            tracing::error!("Failed to run database migrations: {e}");
            return Err(e.into());
        }
        tracing::info!("Database migrations complete");
    }

    tracing::info!("Database connected");

    if let Err(e) = mokosh_server::modules::auth::bootstrap::maybe_bootstrap_admin(&db).await {
        tracing::warn!("Admin bootstrap failed: {}", e);
    }

    // PMS-295: mokosh-auth (mechanism 2, mokosh's own OIDC OP) has been
    // removed. The server now authenticates exclusively via the bunyip-as-OP
    // Resource-Server path (OIDC_ISSUER / OIDC_AUDIENCE, wired below) and the
    // legacy HS256 cookie path. There is no second OP and no /oauth2/* surface
    // hosted by mokosh; bunyip is the sole OP.
    tracing::info!(
        "Auth: bunyip-as-OP Resource-Server + legacy HS256 cookie (mokosh-auth removed)"
    );

    let encryption_key = mokosh_server::utils::crypto::parse_encryption_key(&config.encryption_key)
        .expect("ENCRYPTION_KEY must be 32 bytes (or 64 hex chars)");

    // PMS-988: initialise the application-tier secret provider so the
    // boot classification (Used / Missing / Shadowed / Misplaced) runs
    // against every declared governed secret. `enforce` is fatal only on
    // Misplaced - the case the epic exists for, where the declared
    // provider holds nothing while another provider does; every other
    // case is a warning that names the feature and lets boot continue.
    //
    // The environment provider reads `{NAME}_FILE` only (BUNYIP-38's
    // `docker inspect` protection); a plain `SMTP_PASSWORD` env var is
    // therefore Missing from the app-tier survey, and MailerConfig still
    // reads it through `config::get` on the configuration-provider path.
    // Routing the SMTP READ through this provider is a follow-up: it
    // needs `{NAME}_FILE` (or a database/Infisical row) to exist on
    // every deployment first, and the migrate CLI (PMS-1012) is the
    // path there. Landing the boot survey now catches a botched
    // migration between the two ends.
    mokosh_server::app_secrets::init_from_env(
        hosting_profile.default_provider_for(ProviderKind::Secrets)?,
        db.clone(),
        encryption_key,
    )
    .await?;

    // PMS-789: load the deployment's product name into the process cache
    // before anything can render it. Warn-and-continue rather than hard-fail:
    // the consumers are display strings with a working default, and refusing to
    // boot over one would be a worse failure than showing "Mokosh".
    if let Err(e) = mokosh_server::modules::settings::app_name::resolve_and_cache(&db).await {
        tracing::warn!(error = %e, "could not load the app-name setting; using the default");
    }

    // Build the host-crate mailer. PMS-638: the config resolves from the
    // DB-backed system email setting when present, otherwise the SMTP_* env
    // vars (the unchanged fallback). Wrapped in a `SharedMailer` so the admin
    // email-settings endpoint can rebuild and swap it live. Hard-fail on
    // misconfiguration so an operator does not learn at 3am that a bad config
    // silently degraded to LogMailer.
    //
    // PMS-1013: the email provider selection is named through `MAIL_PROVIDER`
    // (`log` or `smtp`), matching `SECRET_BACKEND` / `STORAGE_BACKEND` for the
    // adjacent seams. The hosting profile supplies the default; an explicit
    // choice overrides. `MAIL_PROVIDER=smtp` with no `SMTP_HOST` refuses to
    // boot (the class of misconfiguration this seam exists to catch), and the
    // selected kind is recorded so `rebuild_and_swap` cannot silently change
    // it at runtime.
    let mail_profile_default = hosting_profile.default_provider_for(ProviderKind::Email)?;
    let mail_config = mokosh_server::utils::email::EmailConfig::from_env(mail_profile_default)?;
    let mail_provider_explicit = mail_config.explicit_providers();
    mokosh_server::utils::email::init_selected_kind(mail_config.provider);
    tracing::info!(
        provider = mail_config.provider.as_str(),
        source = mail_config.source.as_str(),
        "email provider selected"
    );
    let mailer_config =
        mokosh_server::modules::settings::email::resolve_mailer_config(&db, &encryption_key)
            .await
            .expect(
                "Failed to load Mailer config from DB settings / SMTP_* env (see .env.example)",
            );
    let initial_mailer =
        mokosh_server::utils::email::build_mailer(mail_config.provider, mailer_config).expect(
            "Failed to build Mailer for the selected MAIL_PROVIDER; see the error above and \
             either set SMTP_HOST for MAIL_PROVIDER=smtp or MAIL_PROVIDER=log to opt out",
        );
    // Verify the transport now, not on the first outbound: an unreachable
    // relay at 3am is a mail we never sent, and pushing the discovery to the
    // first send is the failure mode PMS-1013 exists to remove. `LogMailer`'s
    // verify is trivially Ok(()), so this line adds a NOOP round-trip on the
    // SMTP path and nothing otherwise.
    if let Err(e) = initial_mailer.verify().await {
        tracing::error!(error = %e, "email provider verify failed");
        return Err(e.into());
    }
    let shared_mailer = std::sync::Arc::new(mokosh_server::utils::email::SharedMailer::new(
        initial_mailer,
    ));
    let mailer: std::sync::Arc<dyn mokosh_server::utils::email::Mailer> = shared_mailer.clone();

    // Bunyip-as-OP Resource-Server verifier. Initialised when OIDC_ISSUER +
    // OIDC_AUDIENCE are set; otherwise the middleware falls back to the legacy
    // HS256 cookie path. See
    // docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md.
    let bunyip_verifier = match mokosh_server::modules::auth::oidc_rs::VerifierConfig::from_env() {
        Ok(cfg) => {
            tracing::info!(issuer = %cfg.issuer, audience = %cfg.audience, "Bunyip RS verifier mounted");
            Some(mokosh_server::modules::auth::oidc_rs::Verifier::new(cfg))
        }
        Err(reason) => {
            tracing::info!(reason = %reason, "Bunyip RS verifier disabled");
            None
        }
    };

    // PMS-981: resolve the authentication provider selection from
    // `AUTH_PROVIDERS` (falling back to the hosting profile's default,
    // which enables both providers) and install it process-wide. Unset
    // means byte-for-byte pre-PMS-981 behaviour. An explicit list that
    // excludes a provider causes the two decision points (bearer verify
    // in `auth_middleware`, password login in `AuthService::login`) to
    // skip that provider as if its underlying capability were not
    // configured, so a rejected credential reads exactly like an
    // invalid one and never discloses the configured set.
    let auth_profile_default = hosting_profile.default_providers_for(ProviderKind::Authentication);
    let auth_chain = mokosh_server::modules::auth::providers::from_env_with(
        auth_profile_default,
        bunyip_verifier.is_some(),
    )?;
    auth_chain.record();
    mokosh_server::modules::auth::providers::install_selection(auth_chain.selection().clone());

    // Notifications dispatcher worker. Drains the `notifications`
    // queue (status='pending' rows) and fires the right transport per
    // row. One worker per replica; concurrent workers SKIP LOCKED
    // their way past each other so it is safe to run several. The
    // tick interval is intentionally low (5s) so transactional
    // emails (password reset, welcome, ticket-note) feel synchronous
    // from the operator's perspective. PMS-198: now runs on the shared
    // Scheduler (registered below) instead of a raw `tokio::spawn`, so
    // it gets the same per-tick tracing span and missed-tick-skip
    // semantics as the other jobs.
    let dispatcher =
        mokosh_server::modules::notifications::DispatcherWorker::new(db.clone(), mailer.clone());

    // RMM device-sync worker. Picks up every active `rmm_connections`
    // row past its `sync_interval_minutes` window, pulls devices via
    // the right `RmmProvider`, UPSERTs `rmm_device_mappings`, links /
    // creates `assets`, and updates `sync_status` / `last_error`.
    // Tick is 60s so the worker fires at minute granularity; per-
    // connection cadence is enforced by the `sync_interval_minutes`
    // gate in its query. PMS-198: migrated onto the shared Scheduler
    // (registered below) alongside the other jobs.
    let rmm_worker = mokosh_server::modules::rmm::RmmSyncWorker::new(db.clone(), encryption_key);

    // Contract lifecycle worker (PMS-64). Sweeps `active` contracts past
    // their `end_date` and renews (auto_renew) or expires them. Contract
    // end_dates are day-granular, so an hourly tick is ample; running it
    // on the shared Scheduler gives it the same per-job tracing span and
    // missed-tick-skip semantics as future renewal/breach jobs.
    let contract_worker = mokosh_server::modules::contracts::ContractLifecycleWorker::new(
        mokosh_server::modules::contracts::ContractsService::new(db.clone()),
    );

    // SLA sweep worker (PMS-106 follow-up). Scans open tickets with SLA
    // due times set and enqueues an at-risk / breach notification the
    // first time each milestone is crossed, deduped via the
    // `sla_notifications` ledger. It needs the notifications dispatcher,
    // so build a NotificationsService clone here (the router builds its
    // own internally). A 60s tick gives minute-granular alerting; the
    // `encryption_key` is `Copy`, so reusing it below for the router is
    // fine.
    let sla_notifications =
        mokosh_server::modules::notifications::NotificationsService::with_encryption_key(
            db.clone(),
            encryption_key,
        );
    let sla_worker = mokosh_server::modules::sla::SlaSweepWorker::new(
        mokosh_server::modules::sla::SlaService::with_dispatcher(db.clone(), sla_notifications),
    );

    // Recurring-invoicing worker (PMS-64 AC5). Each tick turns every
    // active, recurring (non-one_time) contract that is due for its
    // current billing period into a draft invoice built from the
    // contract's recurring items, idempotently per period via the
    // `contract_invoice_runs` ledger. Billing periods are day-granular, so
    // an hourly tick is ample; the ledger makes extra ticks within a
    // period no-ops, so the interval is not load-bearing. The encryption
    // key matches the router's BillingService so the construction is
    // uniform (recurring invoicing never touches gateway-config secrets).
    let recurring_invoicing_worker = mokosh_server::modules::billing::RecurringInvoicingWorker::new(
        mokosh_server::modules::billing::BillingService::with_encryption_key(
            db.clone(),
            encryption_key,
        ),
    );

    // PMS-968: the secret provider, built once for the whole process. A
    // misconfigured provider ends startup here rather than surfacing when a
    // customer tries to pay. Built before the scheduler because the credential
    // mover needs it, and shared with the router below so every reader of a
    // gateway credential is looking in the same place.
    // The hosting profile's default is resolved HERE and handed in as a name
    // (PMS-1011). `secrets` never holds the deployment shape, which is what
    // keeps PMS-904's boundary intact.
    let (secrets, secrets_config) = mokosh_server::secrets::provider_from_env(
        db.clone(),
        encryption_key,
        hosting_profile
            .default_provider_for(ProviderKind::Secrets)
            .expect("secrets profile default"),
    )
    .expect("secret provider configuration");

    // PMS-958: the object provider, built once for the whole process for the
    // same reason. Every service that keeps bytes reaches it through
    // `storage::shared()` rather than a constructor argument (there are
    // thirteen of those constructions across the router, the tenants routes,
    // billing and the seeders), so this first touch is what turns a
    // misconfigured provider into a boot failure instead of a 500 on the first
    // upload.
    let storage_default = hosting_profile
        .default_provider_for(ProviderKind::Storage)
        .expect("storage profile default");
    let (storage_provider, storage_source) = mokosh_server::storage::init_from_env(storage_default)
        .expect("storage provider configuration");

    // PMS-1011: the boot record. Every provider kind, what serves it, and
    // whether the hosting profile's default stands or the operator overrode
    // it, so a provider left on by a default is in the log rather than
    // assumed; PMS-989 reports the deviations from here.
    //
    // The overrides are what the capabilities above already resolved, not a
    // re-read of their variables: each owns the one reader of its own setting,
    // and a second reader here is how two parts of one process come to
    // disagree about what is serving a capability.
    let provider_selection = hosting_profile.resolve_providers(
        &ProviderOverrides::new()
            .with_opt(
                ProviderKind::Configuration,
                config_selection.explicit_providers(),
            )
            .with_opt(ProviderKind::Secrets, secrets_config.explicit_providers())
            .with_opt(
                ProviderKind::Storage,
                (storage_source == EnablementSource::Explicit)
                    .then(|| vec![storage_provider.as_str()]),
            )
            // A mounted verifier is what makes bunyip the platform
            // authenticator, in either mode; the legacy path stays enabled
            // behind it until PMS-981 deprecates it.
            .with_opt(
                ProviderKind::Authentication,
                bunyip_verifier.is_some().then(|| {
                    vec![
                        mokosh_server::utils::deployment::provider::BUNYIP,
                        mokosh_server::utils::deployment::provider::LOCAL,
                    ]
                }),
            )
            .with_opt(ProviderKind::Email, mail_provider_explicit),
    );
    provider_selection.record();

    let mut scheduler = mokosh_server::scheduler::Scheduler::new();
    // PMS-198: the notifications dispatcher (5s) and RMM sync (60s) workers
    // now run on the Scheduler too; the intervals match their former raw
    // `tokio::spawn(run_forever(..))` cadences.
    scheduler.register(dispatcher, std::time::Duration::from_secs(5));
    scheduler.register(rmm_worker, std::time::Duration::from_secs(60));
    scheduler.register(contract_worker, std::time::Duration::from_secs(3600));
    scheduler.register(
        recurring_invoicing_worker,
        std::time::Duration::from_secs(3600),
    );
    scheduler.register(sla_worker, std::time::Duration::from_secs(60));

    // Appointment-reminder worker (PMS-58 follow-up). Each 60s tick
    // enumerates appointment occurrences whose reminder fire-time has
    // arrived and dispatches `appointment.reminder` through the
    // notifications queue, deduping per occurrence+offset via the
    // `appointment_reminders` ledger. 60s matches the minute granularity
    // of `reminder_minutes`. The CalendarService is built with its own
    // NotificationsService clone so the worker can fan out.
    let calendar_notifications =
        mokosh_server::modules::notifications::NotificationsService::with_encryption_key(
            db.clone(),
            encryption_key,
        );
    let calendar_reminder_worker = mokosh_server::modules::calendar::CalendarReminderWorker::new(
        mokosh_server::modules::calendar::CalendarService::with_dispatcher(
            db.clone(),
            calendar_notifications,
        ),
    );
    scheduler.register(calendar_reminder_worker, std::time::Duration::from_secs(60));

    // PMS-478: scheduled-report worker. Ticks every 60s; the cadence
    // matches the cron-expression granularity (cron crate parses
    // minute-level fields, so a sub-minute tick adds nothing). The
    // worker enqueues `email` notifications which the dispatcher
    // (5s tick) flushes to SMTP.
    let scheduled_reports_worker =
        mokosh_server::modules::saved_reports::ScheduledReportsWorker::new(
            db.clone(),
            std::sync::Arc::new(
                mokosh_server::modules::saved_reports::SavedReportsService::new(db.clone()),
            ),
        );
    scheduler.register(scheduled_reports_worker, std::time::Duration::from_secs(60));

    // PMS-471: scheduled-dashboard worker. Same shape as the
    // scheduled-report worker above but ranges over `scheduled_dashboards`
    // and renders a text snapshot of the dashboard layout.
    let scheduled_dashboards_worker =
        mokosh_server::modules::dashboards::ScheduledDashboardsWorker::new(
            db.clone(),
            std::sync::Arc::new(mokosh_server::modules::dashboards::DashboardsService::new(
                db.clone(),
            )),
        );
    scheduler.register(
        scheduled_dashboards_worker,
        std::time::Duration::from_secs(60),
    );
    // mokosh-contact-login: portal_export_worker retired with the
    // /portal/* customer-portal surface. The contact plane replaces
    // it in prompt 004+; export gets rebuilt if the operator still
    // needs it on the contact side.

    // PMS-960: one-shot in effect. A KB attachment used to be stored at a
    // flat `kb-articles/{id}` with no tenant in the path; it is now under
    // its tenant like everything else, and this walks the files already on
    // the volume over to it. The Scheduler fires every job once immediately
    // at startup, so the work happens at boot without blocking it, and the
    // hourly interval is what makes a failed rename retry rather than wait
    // for the next restart. Once every file has moved the tick is one query
    // that returns no rows.
    let kb_attachment_mover =
        mokosh_server::modules::knowledge_base::KbAttachmentMover::new(db.clone());
    scheduler.register(kb_attachment_mover, std::time::Duration::from_secs(3600));

    // One-shot move of the live tenant logo out of the shared `tenant-logos/`
    // directory and under its own tenant, the same shape as the KB mover above
    // and for the same reason: the layout changed, and the files already on the
    // volume did not. `TenantLogoStore::read` falls back to the old location
    // until this has reached them, so a logo keeps rendering in the meantime.
    let tenant_logo_mover = mokosh_server::modules::tenants::TenantLogoMover::new(db.clone());
    scheduler.register(tenant_logo_mover, std::time::Duration::from_secs(3600));

    // PMS-968: one-shot move of pre-existing gateway credentials into the
    // configured secret provider. The scheduler fires every job once at startup,
    // so an hour gives the one-shot behaviour plus a retry if the store was
    // briefly unreachable, and once the move is done the tick is one query
    // returning no rows.
    let gateway_credential_mover = mokosh_server::modules::billing::GatewayCredentialMover::new(
        db.clone(),
        secrets.clone(),
        encryption_key,
    );
    scheduler.register(
        gateway_credential_mover,
        std::time::Duration::from_secs(3600),
    );
    // PMS-1037: overdue invoice reminders, hourly so each tenant's local
    // sending hour is hit once a day. Built with delivery (the mailer and the
    // portal origin) because it mails, unlike the recurring generator above.
    let invoice_reminder_worker = mokosh_server::modules::billing::InvoiceReminderWorker::new(
        mokosh_server::modules::billing::BillingService::with_delivery(
            db.clone(),
            encryption_key,
            mailer.clone(),
            config.spa_base_url.clone(),
            secrets.clone(),
        ),
    );
    scheduler.register(
        invoice_reminder_worker,
        std::time::Duration::from_secs(3600),
    );

    let _scheduler_handles = scheduler.start();

    // PMS-657: build the IP -> country resolver for login-location alerts.
    // Optional: an unset path or a failed .BIN load leaves it None and the
    // alerts stay disabled (login is never affected).
    let geoip = match config.ip2location_db_path.as_deref() {
        Some(path) => match mokosh_server::utils::geoip::GeoIpService::new(path) {
            Ok(svc) => {
                tracing::info!(path = %path, "GeoIP (IP2Location) service initialized");
                Some(std::sync::Arc::new(svc))
            }
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "Failed to load IP2Location DB; login-location alerts disabled");
                None
            }
        },
        None => {
            tracing::info!("IP2LOCATION_DB_PATH unset; login-location alerts disabled");
            None
        }
    };

    // BUNYIP-475: build the advisory ASN / VPN enrichment service (shared
    // dunite-ipenrich crate). Optional and independent of geoip: an unset path or
    // a failed .BIN load leaves it None and the admin enrichment lookup reports
    // nothing (never fatal, mirroring geoip).
    let ip_enrich: Option<std::sync::Arc<dunite_ipenrich::IpEnrichService>> = match config
        .ip2proxy_db_path
        .as_deref()
    {
        Some(path) => match dunite_ipenrich::IpEnrichService::new(path) {
            Ok(svc) => {
                tracing::info!(path = %path, "IP enrichment (IP2Proxy) service initialized");
                Some(std::sync::Arc::new(svc))
            }
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "Failed to load IP2Proxy DB; IP enrichment disabled");
                None
            }
        },
        None => {
            tracing::info!("IP2PROXY_DB_PATH unset; IP enrichment disabled");
            None
        }
    };

    let psa_router = create_api_router(
        db.clone(),
        config.jwt_secret,
        config.client_origin,
        config.spa_base_url,
        config.cors_origins,
        bunyip_verifier,
        shared_mailer,
        encryption_key,
        config.bunyip_webhook_secret.into_bytes(),
        geoip,
        ip_enrich,
        config.login_approval_enabled,
        config.abuse_contact_email,
        config.public_api_base_url,
        config.max_tenants,
        config.deployment_mode,
        secrets.clone(),
    );
    let router = psa_router;

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Server listening on http://{}", addr);

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Run an operator subcommand folded into this binary (PMS-494) and exit,
/// mapping any error to a non-zero process exit. Mirrors the old
/// `mokosh-bootstrap` CLI: load `.env.infisical` then `.env` so credentials can
/// be read from the environment without exporting them onto the command line,
/// and use a plain `info`-default tracing filter (not the server's `debug`
/// one). Dispatch lives in [`mokosh_server::cli`].
async fn run_cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::from_filename(".env.infisical");
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = mokosh_server::cli::run(args).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // PMS-499: the dev fallbacks for JWT_SECRET / ENCRYPTION_KEY are only
    // allowed in dev/test. Every other environment must supply a real secret.
    #[test]
    fn env_allows_dev_secrets_only_in_dev_test() {
        for env in ["development", "dev", "test"] {
            assert!(
                env_allows_dev_secrets(env),
                "{env} should allow dev secrets"
            );
        }
        for env in ["production", "staging", "prod", "", "Development", "qa"] {
            assert!(
                !env_allows_dev_secrets(env),
                "{env} must NOT allow dev secrets"
            );
        }
    }

    // PMS-498: outside dev/test the ENCRYPTION_KEY must be the 64-hex form.
    #[test]
    fn is_hex64_accepts_only_64_hex_chars() {
        assert!(is_hex64(&"ab".repeat(32)), "64 hex chars must be accepted");
        assert!(is_hex64(&"00".repeat(32)));
        assert!(!is_hex64(&"ab".repeat(31)), "63 chars too short");
        assert!(!is_hex64(&"ab".repeat(33)), "66 chars too long");
        assert!(
            !is_hex64("32-byte-key-for-dev-only-change!"),
            "raw 32-byte dev key is not 64 hex"
        );
        assert!(
            !is_hex64(&"zz".repeat(32)),
            "64 non-hex chars must be rejected"
        );
    }

    // PMS-982: the rule is driven with values rather than by mutating
    // process-global environment. `resolve_secret` reads through the held
    // configuration generation now, so a `set_var` here would not have been
    // seen; taking the value also removes the per-test unique var names these
    // needed to avoid racing each other.
    #[test]
    fn resolve_secret_dev_env_falls_back() {
        let got = resolve_secret_value("A_SECRET", None, "development", "the-dev-value").unwrap();
        assert_eq!(got, "the-dev-value");
        // A forwarded-but-unset variable arrives blank (PMS-836) and means the
        // same thing as absent.
        let blank =
            resolve_secret_value("A_SECRET", Some(String::new()), "dev", "the-dev-value").unwrap();
        assert_eq!(blank, "the-dev-value");
    }

    #[test]
    fn resolve_secret_prod_unset_is_fatal() {
        assert!(
            resolve_secret_value("A_SECRET", None, "production", "the-dev-value").is_err(),
            "unset secret in production must error"
        );
    }

    #[test]
    fn resolve_secret_prod_dev_value_is_fatal() {
        assert!(
            resolve_secret_value(
                "A_SECRET",
                Some("the-dev-value".to_string()),
                "production",
                "the-dev-value"
            )
            .is_err(),
            "explicit dev fallback in production must error"
        );
    }

    #[test]
    fn resolve_secret_prod_real_value_ok() {
        let result = resolve_secret_value(
            "A_SECRET",
            Some("a-real-production-secret".to_string()),
            "production",
            "the-dev-value",
        );
        assert_eq!(result.unwrap(), "a-real-production-secret");
    }

    // PMS-497: outside dev/test a JWT_SECRET below the 32-byte HS256 margin is
    // rejected; dev/test accept any length.
    #[test]
    fn jwt_secret_len_dev_test_accepts_short() {
        for env in ["development", "dev", "test"] {
            assert!(check_jwt_secret_len("short", env).is_ok());
        }
    }

    #[test]
    fn jwt_secret_len_prod_rejects_too_short() {
        let short = "x".repeat(MIN_JWT_SECRET_LEN - 1);
        assert!(check_jwt_secret_len(&short, "production").is_err());
        assert!(check_jwt_secret_len(&short, "staging").is_err());
    }

    #[test]
    fn jwt_secret_len_prod_accepts_long_enough() {
        let ok = "a".repeat(MIN_JWT_SECRET_LEN);
        assert!(check_jwt_secret_len(&ok, "production").is_ok());
    }

    // PMS-1160: the essential deployment-shape variables list is closed and
    // ordered. Its shape is source-tested here rather than at boot so the
    // gates below cannot be circumvented by adding a sixth entry that fails
    // to name its purpose or example.
    #[test]
    fn every_essential_requirement_names_its_options_or_shows_an_example() {
        for req in ESSENTIAL_DEPLOYMENT_REQUIREMENTS {
            assert!(
                !req.purpose.is_empty(),
                "{}: purpose must not be empty",
                req.name
            );
            assert!(
                !req.example.is_empty(),
                "{}: example must not be empty",
                req.name
            );
            assert!(
                req.example.contains(req.name),
                "{}: example must show the variable being set (name found in example)",
                req.name
            );
        }
    }

    // PMS-1160: the five variables named by the ticket are the exact ones the
    // list carries. A sixth entry added without moving the ticket is a change
    // the list intends to refuse; adding one deliberately means updating this
    // test and the ticket in the same PR.
    #[test]
    fn the_essential_set_is_exactly_the_pms_1160_five() {
        let names: Vec<&str> = ESSENTIAL_DEPLOYMENT_REQUIREMENTS
            .iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(
            names,
            vec![
                "MOKOSH_DEPLOYMENT_MODE",
                "MOKOSH_APP_DATABASE_URL",
                "BASE_URL",
                "CLIENT_ORIGIN",
                "SPA_BASE_URL",
            ],
            "the essential requirements list must match PMS-1160 exactly; \
             adding a new entry means updating this assertion and the ticket \
             in the same PR"
        );
    }

    // PMS-1160: a `MOKOSH_DEPLOYMENT_MODE` failure names both legal values so
    // an operator does not have to look up `.env.example` to know what to
    // write. The two open-set URL requirements do not print an "Available
    // options" line at all.
    #[test]
    fn format_missing_requirement_names_options_when_closed() {
        let mode = &ESSENTIAL_DEPLOYMENT_REQUIREMENTS[0];
        assert_eq!(mode.name, "MOKOSH_DEPLOYMENT_MODE");
        let msg = format_missing_requirement(mode, "staging");
        assert!(
            msg.contains("Available options: self-hosted | saas"),
            "{msg}"
        );
        assert!(msg.contains("MOKOSH_DEPLOYMENT_MODE=saas"), "{msg}");
        assert!(msg.contains("'staging' environment"), "{msg}");

        let app_db = &ESSENTIAL_DEPLOYMENT_REQUIREMENTS[1];
        assert_eq!(app_db.name, "MOKOSH_APP_DATABASE_URL");
        let msg = format_missing_requirement(app_db, "production");
        assert!(
            !msg.contains("Available options:"),
            "an open-set requirement must not print an Available options line: {msg}"
        );
        assert!(msg.contains("postgres://mokosh_app"), "{msg}");
    }

    // PMS-1160: the gate is off in dev/test. A dev box that never touches
    // these variables must still boot, or `just dev` breaks for everyone.
    #[test]
    fn check_deployment_requirements_no_op_in_dev_and_test() {
        for env in ["development", "dev", "test"] {
            assert!(
                check_deployment_requirements(env).is_ok(),
                "{env}: the gate must not fire in dev/test"
            );
        }
    }
}
