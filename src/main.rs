//! Mokosh Server - API server entrypoint

use mokosh_server::{api::create_api_router, Database};
use std::net::SocketAddr;
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
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();

        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/mokosh".to_string()),
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

    tracing::info!("Starting Mokosh Server");

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
            let verifier =
                mokosh_server::modules::auth::at_jwt::AtJwtVerifier::new(auth.provider.keys.clone(), issuer);
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

    let psa_router = create_api_router(db.clone(), config.jwt_secret, at_jwt);
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
