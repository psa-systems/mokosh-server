//! Embedded migrations. The `migrations/` directory ships inside this
//! crate (and ultimately inside the future `mokosh-auth` repo), separate
//! from `mokosh-server`'s top-level migrations directory.

use mokosh_auth_core::AuthError;

use crate::pool::AuthPool;

/// Apply all pending mokosh_auth migrations. Idempotent.
pub async fn run_migrations(pool: &AuthPool) -> Result<(), AuthError> {
    sqlx::migrate!("./migrations")
        .run(pool.pg())
        .await
        .map_err(|e| AuthError::Storage(format!("migrations failed: {e}")))
}
