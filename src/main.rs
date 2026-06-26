//! Mokosh Server - API server entrypoint

use mokosh_server::{api::create_api_router, version::VersionInfo, Database};
use std::net::SocketAddr;
use std::sync::Arc;
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
    /// Exact origin allowed to receive `postMessage` from the Google
    /// OAuth callback HTML (the SPA's browser-visible origin).
    pub client_origin: String,
    /// All origins permitted to make credentialed CORS requests against
    /// the API. Defaults to `[client_origin]` if `CORS_ORIGIN` is unset.
    /// Set via the `CORS_ORIGIN` env var as a comma-separated list (e.g.
    /// staging `https://msp.a8n.systems,https://a8n.systems`, prod
    /// `https://msp.psa.systems,https://psa.systems`).
    pub cors_origins: Vec<String>,
    /// Lowercased exact-email allowlist; only these emails may auto-provision
    /// a super_admin on first Google sign-in (everyone else is rejected).
    pub oauth_super_admin_emails: Vec<String>,
}

/// Dev-only fallback for `JWT_SECRET`. Accepted only in dev/test
/// environments; in any other environment its presence (or an unset
/// `JWT_SECRET`) is a fatal boot error (PMS-499).
const DEV_JWT_SECRET: &str = "development-secret-change-in-production";
/// Dev-only fallback for `ENCRYPTION_KEY`. Same production guard as
/// [`DEV_JWT_SECRET`] (PMS-499).
const DEV_ENCRYPTION_KEY: &str = "32-byte-key-for-dev-only-change!";

/// True for the environments that may use the hardcoded dev fallbacks.
/// Anything else (staging, production, or an unrecognized value) fails
/// safe: it must supply real secrets. Mirrors [`AppConfig::is_dev_or_test`]
/// but works on the raw env string before the struct is built.
fn env_allows_dev_secrets(environment: &str) -> bool {
    matches!(environment, "development" | "dev" | "test")
}

/// Resolve a secret env var, refusing the dev fallback outside dev/test.
/// In dev/test an unset var falls back to `dev_value`. In every other
/// environment an unset var - or one explicitly set to `dev_value` - is a
/// fatal boot error, consistent with the other fail-loud startup checks
/// (SMTP/Google/migrations) (PMS-499).
fn resolve_secret(
    var_name: &str,
    environment: &str,
    dev_value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match std::env::var(var_name) {
        Ok(value) if !value.is_empty() => {
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
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();

        // Exact-email allowlist (fail-closed): empty by default so no Google
        // identity can self-provision a super_admin until an operator sets
        // OAUTH_SUPER_ADMIN_EMAILS explicitly.
        let oauth_super_admin_emails = std::env::var("OAUTH_SUPER_ADMIN_EMAILS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let environment =
            std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

        // PMS-499: refuse the hardcoded dev fallbacks for the auth/crypto
        // secrets outside dev/test. Resolved before the struct is built so a
        // production/staging/unknown environment fails loud at boot rather than
        // silently serving with a publicly-known JWT_SECRET / ENCRYPTION_KEY.
        let jwt_secret = resolve_secret("JWT_SECRET", &environment, DEV_JWT_SECRET)?;
        let encryption_key = resolve_secret("ENCRYPTION_KEY", &environment, DEV_ENCRYPTION_KEY)?;

        Ok(Self {
            database_url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://postgres:postgres@localhost:5432/mokosh".to_string()
            }),
            // PMS-285: the request-serving role. Default to DATABASE_URL so a
            // dev box without the split still boots (RLS stays inert until the
            // app role is a NOBYPASSRLS one).
            app_database_url: std::env::var("MOKOSH_APP_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .unwrap_or_else(|_| {
                    "postgres://postgres:postgres@localhost:5432/mokosh".to_string()
                }),
            jwt_secret,
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            environment,
            base_url: std::env::var("BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            run_migrations: std::env::var("RUN_MIGRATIONS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            encryption_key,
            client_origin: std::env::var("CLIENT_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:4301".to_string()),
            cors_origins: std::env::var("CORS_ORIGIN")
                .ok()
                .map(|raw| {
                    raw.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| {
                    vec![std::env::var("CLIENT_ORIGIN")
                        .unwrap_or_else(|_| "http://localhost:4301".to_string())]
                }),
            oauth_super_admin_emails,
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

    let config = AppConfig::from_env().expect("Failed to load configuration");

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
    // consistent with the other startup checks (SMTP/Google/ENCRYPTION_KEY/CORS
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

    // Try to bootstrap mokosh-auth first so the resulting key set can
    // be passed into the PSA router as the at+jwt verifier. The PSA
    // middleware then accepts SSO-issued access tokens alongside its
    // own legacy HS256 cookies.
    // SAFETY (PMS-285): SSO bootstrap registers OAuth clients and seeds the
    // mokosh_auth schema (DDL/system rows) before any request is served, so it
    // runs on the privileged migrator pool, not the NOBYPASSRLS app pool.
    let (sso_router, at_jwt) = match try_bootstrap_sso(db.migrator_pool().clone()).await {
        Ok(SsoSetup::Mounted(auth)) => {
            tracing::info!("SSO subsystem mounted (mokosh-auth)");
            let issuer = auth.provider.cfg.issuer.as_str().to_string();
            let verifier = mokosh_server::modules::auth::at_jwt::AtJwtVerifier::new(
                auth.provider.keys.clone(),
                issuer,
            );
            (Some(auth.router()), Some(verifier))
        }
        Ok(SsoSetup::NotConfigured) => {
            // PMS-291: mokosh-auth (mechanism 2) is one of three independent
            // auth paths. Not mounting it leaves the bunyip-as-OP
            // Resource-Server path (mechanism 1, OIDC_ISSUER / OIDC_AUDIENCE)
            // AND the legacy HS256 cookie path (mechanism 3) both active. The
            // earlier "the server will run with legacy auth only" phrasing was
            // misleading: it implied a full fallback to mechanism 3, which is
            // not what happens. Be explicit about what stays on so an operator
            // grepping logs cannot conclude bunyip auth is also down.
            tracing::warn!(
                "mokosh-auth OP (mechanism 2) not configured. The server is still serving the \
                 bunyip-as-OP Resource-Server path (OIDC_ISSUER/OIDC_AUDIENCE) and the legacy \
                 HS256 cookie path; only mokosh's own /oauth2/* endpoints are unavailable. \
                 To enable mechanism 2, set MOKOSH_AUTH_ISSUER, \
                 MOKOSH_AUTH_JWT_PRIVATE_KEY_PATH, MOKOSH_AUTH_JWT_ACTIVE_KID, \
                 MOKOSH_AUTH_JWT_PUBLIC_KEYS_DIR, and MOKOSH_AUTH_DATA_ENCRYPTION_KEY."
            );
            (None, None)
        }
        // PMS-289: SSO IS configured (MOKOSH_AUTH_* set) but failed to
        // bootstrap - invalid config, or migrations / key load failed. Fail
        // loud and exit non-zero rather than silently downgrade to legacy auth,
        // which would drop the OIDC / at+jwt verification path with only a WARN.
        Err(e) => {
            tracing::error!("SSO is configured but failed to bootstrap: {e}");
            return Err(e);
        }
    };

    // Build the Google OAuth client from env. Hard-fail at startup if the
    // env vars are missing - the /api/v1/auth/google routes would 500 on
    // every request otherwise, which is harder to diagnose.
    let google_oauth_config = google_oauth_flow::Config::from_env()
        .expect("Failed to read GOOGLE_OAUTH_* env (see .env.example)");
    let google_oauth = Arc::new(
        google_oauth_flow::Client::new(google_oauth_config)
            .expect("Failed to build Google OAuth client (invalid redirect URI?)"),
    );

    // Browsers drop `Secure` cookies on plain HTTP, so disable the flag
    // only in dev/test. Everywhere else (staging, production, or an
    // unrecognized ENVIRONMENT) defaults to secure so the OAuth state
    // cookie is not exposed over a downgraded connection.
    let cookie_secure = !config.is_dev_or_test();

    // Build the host-crate mailer (SmtpMailer when SMTP_HOST is set,
    // LogMailer otherwise). Hard-fail on misconfiguration so an
    // operator does not learn at 3am that SMTP_USERNAME without
    // SMTP_PASSWORD silently degraded to LogMailer.
    let mailer = mokosh_server::utils::email::MailerConfig::from_env()
        .and_then(|c| c.build())
        .expect("Failed to build Mailer from SMTP_* env (see .env.example)");

    let encryption_key = mokosh_server::utils::crypto::parse_encryption_key(&config.encryption_key)
        .expect("ENCRYPTION_KEY must be 32 bytes (or 64 hex chars)");

    // Bunyip-as-OP Resource-Server verifier. Initialised when OIDC_ISSUER +
    // OIDC_AUDIENCE are set; otherwise the middleware falls back to the legacy
    // mokosh-auth at+jwt + HS256 cookie paths. See
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
                mokosh_server::modules::saved_reports::SavedReportsService::new(db.pool().clone()),
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
                db.pool().clone(),
            )),
        );
    scheduler.register(
        scheduled_dashboards_worker,
        std::time::Duration::from_secs(60),
    );
    let _scheduler_handles = scheduler.start();

    let psa_router = create_api_router(
        db.clone(),
        config.jwt_secret,
        google_oauth,
        config.client_origin,
        config.cors_origins,
        config.oauth_super_admin_emails,
        cookie_secure,
        at_jwt,
        bunyip_verifier,
        mailer,
        encryption_key,
    );
    let router = match sso_router {
        Some(sso) => psa_router.merge(sso),
        None => psa_router,
    };

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

/// Outcome of the SSO subsystem setup (PMS-289). Distinguishes "SSO was never
/// configured" (a legitimate legacy-only deployment) from "SSO is configured
/// but failed to bootstrap" (a real error). The latter is returned as `Err`
/// from [`try_bootstrap_sso`] and is fatal at the call site - silently running
/// legacy-only when SSO was meant to be on is a security-relevant downgrade
/// (the OIDC / at+jwt verification path just disappears), not a graceful
/// fallback.
enum SsoSetup {
    /// Configured and bootstrapped: mount the router + at+jwt verifier.
    Mounted(Box<mokosh_auth::MokoshAuth>),
    /// No `MOKOSH_AUTH_*` env set: the operator did not enable SSO.
    NotConfigured,
}

/// The required env vars that signal "SSO is intended". If any is set, SSO is
/// configured and a bootstrap failure must be fatal; if none is set, SSO is off
/// and the server runs legacy-only.
const SSO_REQUIRED_ENV: [&str; 5] = [
    "MOKOSH_AUTH_ISSUER",
    "MOKOSH_AUTH_JWT_PRIVATE_KEY_PATH",
    "MOKOSH_AUTH_JWT_ACTIVE_KID",
    "MOKOSH_AUTH_JWT_PUBLIC_KEYS_DIR",
    "MOKOSH_AUTH_DATA_ENCRYPTION_KEY",
];

fn sso_is_configured() -> bool {
    SSO_REQUIRED_ENV
        .iter()
        .any(|k| std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false))
}

/// Bootstrap the SSO subsystem when it is configured. Returns
/// [`SsoSetup::NotConfigured`] (run legacy-only) when no `MOKOSH_AUTH_*` env is
/// set, [`SsoSetup::Mounted`] on success, or `Err` (fatal) when SSO IS
/// configured but `from_env` (partial/invalid config) or `bootstrap`
/// (migrations, key load) fails - so a misconfigured-but-intended SSO never
/// silently degrades to legacy auth (PMS-289).
async fn try_bootstrap_sso(pool: sqlx::PgPool) -> Result<SsoSetup, Box<dyn std::error::Error>> {
    if !sso_is_configured() {
        return Ok(SsoSetup::NotConfigured);
    }
    let auth_cfg = mokosh_auth::AuthConfig::from_env()?;
    let auth = mokosh_auth::bootstrap(auth_cfg, pool).await?;
    Ok(SsoSetup::Mounted(Box::new(auth)))
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

    // Use a per-test unique var name so the env mutation cannot collide with
    // sibling tests running in the same process.
    #[test]
    fn resolve_secret_dev_env_falls_back() {
        let var = "PMS499_TEST_DEV_FALLBACK";
        std::env::remove_var(var);
        let got = resolve_secret(var, "development", "the-dev-value").unwrap();
        assert_eq!(got, "the-dev-value");
    }

    #[test]
    fn resolve_secret_prod_unset_is_fatal() {
        let var = "PMS499_TEST_PROD_UNSET";
        std::env::remove_var(var);
        assert!(
            resolve_secret(var, "production", "the-dev-value").is_err(),
            "unset secret in production must error"
        );
    }

    #[test]
    fn resolve_secret_prod_dev_value_is_fatal() {
        let var = "PMS499_TEST_PROD_DEVVAL";
        std::env::set_var(var, "the-dev-value");
        let result = resolve_secret(var, "production", "the-dev-value");
        std::env::remove_var(var);
        assert!(
            result.is_err(),
            "explicit dev fallback in production must error"
        );
    }

    #[test]
    fn resolve_secret_prod_real_value_ok() {
        let var = "PMS499_TEST_PROD_REAL";
        std::env::set_var(var, "a-real-production-secret");
        let result = resolve_secret(var, "production", "the-dev-value");
        std::env::remove_var(var);
        assert_eq!(result.unwrap(), "a-real-production-secret");
    }

    // PMS-289: the fatal-vs-degrade decision hinges on this intent detector -
    // none of the MOKOSH_AUTH_* env set means "SSO off, run legacy" (degrade);
    // any set means "SSO intended" so a later bootstrap failure must be fatal.
    #[test]
    fn sso_is_configured_tracks_env_presence() {
        // Snapshot then clear the SSO env so the assertions are deterministic.
        let saved: Vec<(&str, Option<String>)> = SSO_REQUIRED_ENV
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        for k in SSO_REQUIRED_ENV {
            std::env::remove_var(k);
        }

        assert!(
            !sso_is_configured(),
            "no MOKOSH_AUTH_* env => SSO not configured"
        );

        std::env::set_var("MOKOSH_AUTH_ISSUER", "https://issuer.test");
        assert!(
            sso_is_configured(),
            "any MOKOSH_AUTH_* env set => SSO configured"
        );

        // Restore the prior environment so sibling tests are unaffected.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}
