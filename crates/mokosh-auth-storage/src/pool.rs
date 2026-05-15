//! PgPool wrapper. Repositories take an `AuthPool` rather than an
//! `sqlx::PgPool` directly so that we can attach pool-wide concerns
//! (statement timeout, search_path, connect-time settings) in one place.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("invalid database url: {0}")]
    InvalidUrl(String),
    #[error("connection error: {0}")]
    Connection(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct AuthPool {
    inner: PgPool,
}

impl AuthPool {
    /// Connect using a database URL. Sets a conservative statement timeout
    /// (5s) so a runaway auth query cannot wedge a connection. Pin the
    /// `mokosh_auth` schema first on the search path so unqualified table
    /// names resolve there even if a future migration forgets a prefix.
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, PoolError> {
        let opts = PgConnectOptions::from_str(database_url)
            .map_err(|e| PoolError::InvalidUrl(e.to_string()))?
            .options([
                ("statement_timeout", "5000"),
                ("search_path", "mokosh_auth, public"),
            ]);

        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;

        Ok(Self { inner: pool })
    }

    /// Wrap an existing pool. Used in tests, and by callers that want to
    /// share a pool with the rest of the application.
    pub fn from_pool(inner: PgPool) -> Self {
        Self { inner }
    }

    pub fn pg(&self) -> &PgPool {
        &self.inner
    }
}
