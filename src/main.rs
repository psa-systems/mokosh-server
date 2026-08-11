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
        check_jwt_secret_len(&jwt_secret, &environment)?;
        let encryption_key = resolve_secret("ENCRYPTION_KEY", &environment, DEV_ENCRYPTION_KEY)?;
        // PMS-591: shared secret for the BUNYIP-211 `account_deleted` webhook.
        // Same fail-loud posture as the other secrets: dev/test may fall back to
        // a hardcoded value, staging/production refuse to boot without a real
        // secret. Matches bunyip-api's `BUNYIP_WEBHOOK_SIGNING_SECRET`
        // (BUNYIP-332); bunyip signs every outbound webhook with a single
        // service-wide secret, not a per-Application value.
        let bunyip_webhook_secret = resolve_secret(
            "BUNYIP_WEBHOOK_SECRET",
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
            bunyip_webhook_secret,
            // PMS-657: optional IP2Location DB path for login-location alerts.
            ip2location_db_path: std::env::var("IP2LOCATION_DB_PATH")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            // BUNYIP-475: optional IP2Proxy PX DB path for ASN / VPN enrichment.
            ip2proxy_db_path: std::env::var("IP2PROXY_DB_PATH")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            // PMS-658: opt-in switch for the suspicious-login notify-and-approve
            // gate. Default false because it can withhold a login; enable per
            // deployment for a staged rollout.
            login_approval_enabled: std::env::var("LOGIN_APPROVAL_ENABLED")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false),
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

    // PMS-295: mokosh-auth (mechanism 2, mokosh's own OIDC OP) has been
    // removed. The server now authenticates exclusively via the bunyip-as-OP
    // Resource-Server path (OIDC_ISSUER / OIDC_AUDIENCE, wired below) and the
    // legacy HS256 cookie path. There is no second OP and no /oauth2/* surface
    // hosted by mokosh; bunyip is the sole OP.
    tracing::info!(
        "Auth: bunyip-as-OP Resource-Server + legacy HS256 cookie (mokosh-auth removed)"
    );

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

    let encryption_key = mokosh_server::utils::crypto::parse_encryption_key(&config.encryption_key)
        .expect("ENCRYPTION_KEY must be 32 bytes (or 64 hex chars)");

    // Build the host-crate mailer. PMS-638: the config resolves from the
    // DB-backed system email setting when present, otherwise the SMTP_* env
    // vars (the unchanged fallback). Wrapped in a `SharedMailer` so the admin
    // email-settings endpoint can rebuild and swap it live. Hard-fail on
    // misconfiguration so an operator does not learn at 3am that a bad config
    // silently degraded to LogMailer.
    let initial_mailer =
        mokosh_server::modules::settings::email::resolve_mailer_config(&db, &encryption_key)
            .await
            .and_then(|c| c.build())
            .expect("Failed to build Mailer from DB settings / SMTP_* env (see .env.example)");
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
    // PMS-729 phase 2 §7 slice D / I15 follow-up: portal data-export
    // worker. 60s tick is generous - customers rarely request more
    // than a handful per tenant per day - and matches the neighbours'
    // cadence so the log lines line up.
    let portal_export_worker =
        mokosh_server::modules::portal::export_worker::PortalExportWorker::new(db.clone());
    scheduler.register(portal_export_worker, std::time::Duration::from_secs(60));
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
        google_oauth,
        config.client_origin,
        config.cors_origins,
        config.oauth_super_admin_emails,
        cookie_secure,
        bunyip_verifier,
        shared_mailer,
        encryption_key,
        config.bunyip_webhook_secret.into_bytes(),
        geoip,
        ip_enrich,
        config.login_approval_enabled,
        mokosh_server::modules::portal::PortalHostConfig::from_env(),
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
}
