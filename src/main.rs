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

    let router = create_api_router(db, config.jwt_secret);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Server listening on http://{}", addr);

    axum::serve(listener, router).await?;

    Ok(())
}
