//! Database connection pool and management

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

use crate::utils::error::{AppError, AppResult};

/// Database connection pool wrapper
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(database_url: &str) -> AppResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .max_lifetime(Duration::from_secs(1800))
            .connect(database_url)
            .await
            .map_err(|e| AppError::Database(format!("Failed to connect to database: {}", e)))?;

        tracing::info!("Connected to database");

        Ok(Self { pool })
    }

    /// Wrap an existing `PgPool`. Used by the integration-test harness
    /// (`tests/common/`) where `#[sqlx::test]` provisions the pool against
    /// a per-test database.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run database migrations.
    ///
    /// `set_ignore_missing(true)` is required because mokosh-auth's
    /// migrations share the same `_sqlx_migrations` table. Without it,
    /// the PSA migrator sees timestamp-versioned auth migrations like
    /// `20260506000001` as "applied but missing in the resolved
    /// source" and refuses to run. Auth migrations live under their
    /// own range so version collisions are impossible.
    pub async fn run_migrations(&self) -> AppResult<()> {
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.set_ignore_missing(true);
        migrator
            .run(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Migration failed: {}", e)))?;

        tracing::info!("Database migrations completed");
        Ok(())
    }

    /// Health check for the database
    pub async fn health_check(&self) -> AppResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Health check failed: {}", e)))?;

        Ok(())
    }

    /// Begin a transaction with the RLS tenant GUC set.
    ///
    /// The `tenant_isolation` RLS policy keys off `app.current_tenant`. It
    /// must be set with `SET LOCAL` (transaction-scoped) via `set_config(..,
    /// true)` - never with a bare `SET` on a pooled connection, which would
    /// leak the tenant context to the next request that reuses that
    /// connection. The value is bound as a parameter (not interpolated) so
    /// there is no SQL-injection surface even though tenant_id is a Uuid.
    ///
    /// The policy is fail-closed as of migration `038_rls_fail_closed.sql`: an
    /// unset GUC matches no rows and a write whose `tenant_id` does not equal
    /// the GUC is rejected (WITH CHECK), with `FORCE ROW LEVEL SECURITY` so the
    /// owner is not exempt. This bites only for connections whose role lacks
    /// BYPASSRLS. The application currently connects as the bypassing
    /// (migration) role and still relies on explicit `WHERE tenant_id = $1`
    /// filters on the read paths not yet moved onto this helper; switching the
    /// app connection to an unprivileged NOBYPASSRLS role is gated on migrating
    /// those remaining paths (parent PMS-255). Queries run through a transaction
    /// from this helper get the tenant GUC set and so satisfy the policy.
    #[cfg(feature = "multi-tenant")]
    pub async fn begin_with_tenant(
        &self,
        tenant_id: impl Into<uuid::Uuid>,
    ) -> AppResult<TenantTransaction<'_>> {
        let tenant_id = tenant_id.into();
        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await?;

        Ok(TenantTransaction { tx, tenant_id })
    }
}

/// A database transaction with tenant context set
#[cfg(feature = "multi-tenant")]
pub struct TenantTransaction<'a> {
    tx: sqlx::Transaction<'a, sqlx::Postgres>,
    tenant_id: uuid::Uuid,
}

#[cfg(feature = "multi-tenant")]
impl<'a> TenantTransaction<'a> {
    pub fn tenant_id(&self) -> uuid::Uuid {
        self.tenant_id
    }

    pub async fn commit(self) -> AppResult<()> {
        self.tx.commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> AppResult<()> {
        self.tx.rollback().await?;
        Ok(())
    }
}

// Deref to the underlying `PgConnection` (one level deeper than the wrapped
// `Transaction`) so the standard sqlx idiom `.execute(&mut *tx)` yields a
// `&mut PgConnection` - exactly as it does for a plain `sqlx::Transaction`.
// sqlx 0.8 does not implement `Executor` for `&mut Transaction`, so deref-ing
// only to `Transaction` would make `&mut *tx` fail to compile at every call
// site. `commit`/`rollback`/`tenant_id` stay as inherent methods above.
#[cfg(feature = "multi-tenant")]
impl<'a> std::ops::Deref for TenantTransaction<'a> {
    type Target = sqlx::PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

#[cfg(feature = "multi-tenant")]
impl<'a> std::ops::DerefMut for TenantTransaction<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}
