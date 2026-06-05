//! Mokosh Server - API server entrypoint

use mokosh_server::{api::create_api_router, version::VersionInfo, Database};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Application configuration loaded from environment
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub database_url: String,
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
    /// `https://msp.a8n.systems,https://a8n.systems`).
    pub cors_origins: Vec<String>,
    /// Lowercased exact-email allowlist; only these emails may auto-provision
    /// a super_admin on first Google sign-in (everyone else is rejected).
    pub oauth_super_admin_emails: Vec<String>,
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

        Ok(Self {
            database_url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://postgres:postgres@localhost:5432/mokosh".to_string()
            }),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "development-secret-change-in-production".to_string()),
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            base_url: std::env::var("BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            run_migrations: std::env::var("RUN_MIGRATIONS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            encryption_key: std::env::var("ENCRYPTION_KEY")
                .unwrap_or_else(|_| "32-byte-key-for-dev-only-change!".to_string()),
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

    #[cfg(feature = "multi-tenant")]
    pub fn is_multi_tenant(&self) -> bool {
        true
    }

    #[cfg(feature = "single-tenant")]
    pub fn is_multi_tenant(&self) -> bool {
        false
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mokosh_server=debug".parse().unwrap())
                .add_directive("tower_http=debug".parse().unwrap()),
        )
        .init();

    tracing::info!("Starting {}", VersionInfo::current().banner());

    #[cfg(feature = "multi-tenant")]
    tracing::info!("Running in multi-tenant mode");

    #[cfg(feature = "single-tenant")]
    tracing::info!("Running in single-tenant mode");

    let config = AppConfig::from_env().expect("Failed to load configuration");

    let db = Database::new(&config.database_url).await?;

    if config.run_migrations {
        match db.run_migrations().await {
            Ok(()) => tracing::info!("Database migrations complete"),
            Err(e) => tracing::warn!("Failed to run migrations: {}", e),
        }
    }

    tracing::info!("Database connected");

    if let Err(e) = mokosh_server::modules::auth::bootstrap::maybe_bootstrap_admin(&db).await {
        tracing::warn!("Admin bootstrap failed: {}", e);
    }

    // Try to bootstrap mokosh-auth first so the resulting key set can
    // be passed into the PSA router as the at+jwt verifier. The PSA
    // middleware then accepts SSO-issued access tokens alongside its
    // own legacy HS256 cookies.
    let (sso_router, at_jwt) = match try_bootstrap_sso(db.pool().clone()).await {
        Ok(auth) => {
            tracing::info!("SSO subsystem mounted (mokosh-auth)");
            let issuer = auth.provider.cfg.issuer.as_str().to_string();
            let verifier = mokosh_server::modules::auth::at_jwt::AtJwtVerifier::new(
                auth.provider.keys.clone(),
                issuer,
            );
            (Some(auth.router()), Some(verifier))
        }
        Err(e) => {
            tracing::warn!(
                "SSO subsystem not mounted: {e}. The server will run with legacy auth only. \
                 Set MOKOSH_AUTH_ISSUER, MOKOSH_AUTH_JWT_PRIVATE_KEY_PATH, \
                 MOKOSH_AUTH_JWT_ACTIVE_KID, MOKOSH_AUTH_JWT_PUBLIC_KEYS_DIR, \
                 and MOKOSH_AUTH_DATA_ENCRYPTION_KEY to enable SSO."
            );
            (None, None)
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
    // in development. In any non-dev environment, set it.
    let cookie_secure = config.is_production();

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
    // from the operator's perspective.
    let dispatcher =
        mokosh_server::modules::notifications::DispatcherWorker::new(db.clone(), mailer.clone());
    tokio::spawn(dispatcher.run_forever(std::time::Duration::from_secs(5), 25));

    // RMM device-sync worker. Picks up every active `rmm_connections`
    // row past its `sync_interval_minutes` window, pulls devices via
    // the right `RmmProvider`, UPSERTs `rmm_device_mappings`, links /
    // creates `assets`, and updates `sync_status` / `last_error`.
    // Tick is 60s so the worker fires at minute granularity; per-
    // connection cadence is enforced by the `sync_interval_minutes`
    // gate in its query.
    let rmm_worker = mokosh_server::modules::rmm::RmmSyncWorker::new(db.clone(), encryption_key);
    tokio::spawn(rmm_worker.run_forever(std::time::Duration::from_secs(60)));

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

    let mut scheduler = mokosh_server::scheduler::Scheduler::new();
    scheduler.register(contract_worker, std::time::Duration::from_secs(3600));
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

/// Try to bootstrap the SSO subsystem. Returns the full `MokoshAuth`
/// handle so the caller can pull both the router and the key set out of
/// it. On failure (typically required env vars not set in dev), the
/// error is surfaced so the caller can fall back to legacy auth only.
async fn try_bootstrap_sso(
    pool: sqlx::PgPool,
) -> Result<mokosh_auth::MokoshAuth, Box<dyn std::error::Error>> {
    let auth_cfg = mokosh_auth::AuthConfig::from_env()?;
    let auth = mokosh_auth::bootstrap(auth_cfg, pool).await?;
    Ok(auth)
}
