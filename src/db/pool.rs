//! Database connection pool and management

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

use crate::utils::error::{AppError, AppResult};

/// Database connection pool wrapper.
///
/// PMS-285: the application runs two connections with different RLS
/// postures so the request-serving connection can no longer bypass the
/// fail-closed `tenant_isolation` policy:
///
/// - `app_pool` connects as the unprivileged `mokosh_app`
///   (`NOSUPERUSER NOBYPASSRLS`) role. Every request-serving query runs
///   here, so a forgotten `WHERE tenant_id` filter is backstopped by RLS:
///   with no `app.current_tenant` GUC set it returns zero rows. `pool()`
///   and `begin_with_tenant` both hand out this connection.
/// - `migrator_pool` connects as the privileged `mokosh_migrator`
///   (`BYPASSRLS`) role that owns the schema. Migrations, bootstrap, the
///   background workers (which sweep across every tenant), and the few
///   legitimately cross-tenant / pre-auth paths run here, each with an
///   explicit `// SAFETY:` note at the call site.
///
/// In dev/CI without the role split, both fields point at the same pool
/// (`from_pool`, or `new` when `MOKOSH_APP_DATABASE_URL` is unset), which
/// preserves the pre-split behaviour. RLS only bites once `app_pool`
/// connects as a NOBYPASSRLS role.
#[derive(Clone)]
pub struct Database {
    app_pool: PgPool,
    migrator_pool: PgPool,
}

impl Database {
    /// Create the two connection pools.
    ///
    /// `app_url` is the request-serving connection string (role
    /// `mokosh_app`, NOBYPASSRLS). `migrator_url` is the privileged
    /// connection string (role `mokosh_migrator`, BYPASSRLS) used for
    /// migrations, bootstrap, workers and cross-tenant paths. Pass the
    /// same URL for both to run without the role split (RLS then does not
    /// bite because the single role bypasses it).
    pub async fn new(app_url: &str, migrator_url: &str) -> AppResult<Self> {
        let migrator_pool = Self::connect(migrator_url, "migrator").await?;
        // When the two URLs are identical, reuse the single pool rather
        // than opening a second identical one.
        let app_pool = if app_url == migrator_url {
            migrator_pool.clone()
        } else {
            Self::connect(app_url, "app").await?
        };

        tracing::info!("Connected to database (app + migrator pools)");

        Ok(Self {
            app_pool,
            migrator_pool,
        })
    }

    async fn connect(database_url: &str, label: &str) -> AppResult<PgPool> {
        PgPoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .max_lifetime(Duration::from_secs(1800))
            .connect(database_url)
            .await
            .map_err(|e| {
                AppError::Database(format!("Failed to connect to database ({label}): {e}"))
            })
    }

    /// Wrap an existing `PgPool` as BOTH pools. Used by the integration-test
    /// harness (`tests/common/`) where `#[sqlx::test]` provisions a single
    /// superuser pool against a per-test database; without the role split
    /// the app and migrator connections coincide and RLS does not bite.
    /// Suites that exercise RLS through the app role build the app pool
    /// separately via [`Self::from_pools`].
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            app_pool: pool.clone(),
            migrator_pool: pool,
        }
    }

    /// Wrap two distinct pools. Used by the RLS-exercising integration
    /// harness, which builds `app_pool` connecting as the unprivileged
    /// `mokosh_app` role and passes the `#[sqlx::test]` superuser pool as
    /// `migrator_pool`.
    pub fn from_pools(app_pool: PgPool, migrator_pool: PgPool) -> Self {
        Self {
            app_pool,
            migrator_pool,
        }
    }

    /// Get a reference to the request-serving (`mokosh_app`, NOBYPASSRLS)
    /// connection pool. Serving queries must either set the
    /// `app.current_tenant` GUC (via [`Self::begin_with_tenant`]) or accept
    /// that RLS fail-closes them to zero rows.
    pub fn pool(&self) -> &PgPool {
        &self.app_pool
    }

    /// Get a reference to the privileged (`mokosh_migrator`, BYPASSRLS)
    /// connection pool. Reserved for migrations, bootstrap, the
    /// cross-tenant background workers, and the explicitly-justified
    /// pre-auth / cross-tenant / system-shared paths. Every call site must
    /// carry a `// SAFETY:` note explaining why it legitimately bypasses
    /// per-tenant RLS.
    pub fn migrator_pool(&self) -> &PgPool {
        &self.migrator_pool
    }

    /// Run database migrations on the privileged migrator pool.
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
            .run(&self.migrator_pool)
            .await
            .map_err(|e| AppError::Database(format!("Migration failed: {}", e)))?;

        tracing::info!("Database migrations completed");
        Ok(())
    }

    /// Health check for the database (request-serving pool).
    pub async fn health_check(&self) -> AppResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.app_pool)
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
    /// BYPASSRLS. As of PMS-285 the request-serving connection (`app_pool`)
    /// runs as the unprivileged `mokosh_app` (NOBYPASSRLS) role, so a serving
    /// query that does NOT go through this helper fail-closes to zero rows.
    /// Transactions opened here set the tenant GUC and so satisfy the policy.
    /// Genuinely cross-tenant / pre-auth paths instead run on
    /// [`Self::migrator_pool`] with an explicit `// SAFETY:` note.
    #[cfg(feature = "multi-tenant")]
    pub async fn begin_with_tenant(
        &self,
        tenant_id: impl Into<uuid::Uuid>,
    ) -> AppResult<TenantTransaction<'_>> {
        let tenant_id = tenant_id.into();
        let mut tx = self.app_pool.begin().await?;

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
