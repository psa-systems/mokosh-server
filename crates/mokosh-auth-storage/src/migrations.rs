//! Embedded migrations. The `migrations/` directory ships inside this
//! crate (and ultimately inside the future `mokosh-auth` repo), separate
//! from `mokosh-server`'s top-level migrations directory.

use mokosh_auth_core::AuthError;

use crate::pool::AuthPool;

/// Apply all pending mokosh_auth migrations. Idempotent.
///
/// `set_ignore_missing(true)` is critical when the auth crates are
/// embedded inside a host application (mokosh-server) that has its
/// own migrations sharing the same `_sqlx_migrations` table. Without
/// it the auth migrator sees PSA migrations 1, 2, ... as "applied
/// but missing in the resolved source" and refuses to run. Auth
/// migrations are versioned with timestamp prefixes
/// (`20260506000001` ...) so they will never collide with PSA's
/// small integer versions.
pub async fn run_migrations(pool: &AuthPool) -> Result<(), AuthError> {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.set_ignore_missing(true);
    migrator
        .run(pool.pg())
        .await
        .map_err(|e| AuthError::Storage(format!("migrations failed: {e}")))
}
