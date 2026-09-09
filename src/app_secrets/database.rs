//! The database provider: encrypted rows in the `app_secrets` table.
//!
//! `app_secrets` is one row per governed secret keyed by [`GovernedSecret::name`]
//! (see migration 207): no tenant column, no RLS, because this tier is
//! application-scope. The value is AES-256-GCM ciphertext under the
//! deployment's `ENCRYPTION_KEY`, which the migrator role owns and the
//! request-serving `mokosh_app` role reads and writes.
//!
//! Every governed secret is loaded once at construction and cached in an
//! `Arc<HashMap>`; the trait's `get` is sync (see the module docs), so a
//! blocking DB call from a request path would either deadlock the runtime
//! or force every caller onto the blocking pool. Once loaded, the
//! classification, `enforce` and every subsequent read hit the cache.
//!
//! Load-once means a save through this provider requires a live reload for
//! this process to see it; that is a future admin-endpoint concern (PMS-1012)
//! and reuses the same `crate::app_secrets::init_from_env` machinery.
//!
//! `crate::utils::crypto::encrypt` and `decrypt` emit base64 strings, not raw
//! bytes, so `ciphertext BYTEA` on the row holds the base64 encoding as
//! bytes: the alternative (rebasing every existing decrypt call in the crate
//! to raw bytes) would touch every per-feature secret column and is out of
//! scope. The column type is still `BYTEA` because a future rewrite of the
//! crypto helpers to hand back bytes lands without a schema change.

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use super::{AppSecretProvider, GovernedSecret};
use crate::db::Database;
use crate::utils::crypto;
use crate::utils::error::{AppError, AppResult};

/// The database-backed application-tier secret provider.
///
/// The cache is populated once by [`DatabaseProvider::load`] and kept in step
/// with the row store through the PMS-1012 write path: [`Self::set`] encrypts,
/// upserts, and updates the cache in one call, so a read immediately after a
/// write returns the value just written. Cross-process writes reach this
/// process on the next boot or the next admin live-reload.
pub struct DatabaseProvider {
    writer: WriteBackend,
    values: RwLock<HashMap<&'static str, String>>,
}

/// The pool half of the provider, split from the cache so unit tests can
/// build the cache without a live pool.
enum WriteBackend {
    /// The real backend: a database pool plus the `ENCRYPTION_KEY` needed to
    /// encrypt on write and decrypt on load.
    Real { db: Database, key: [u8; 32] },
    /// A test-only sentinel; every `set`/`delete` refuses so unit tests that
    /// only exercise the read path stay pool-free.
    #[cfg(test)]
    Disabled,
}

impl DatabaseProvider {
    /// Read every governed secret's row from `app_secrets`, decrypt it, and
    /// cache the plaintext keyed by [`GovernedSecret::name`].
    ///
    /// A row that decrypts to an empty string, or a row that fails to
    /// decrypt (the key set does not cover it), is treated as unheld: the
    /// classification then reports "database does not hold this" honestly
    /// rather than pretending to hold a value it cannot use, which is the
    /// same rule Bunyip's `decrypt_column` follows (BUNYIP-621).
    pub async fn load(db: &Database, encryption_key: [u8; 32]) -> AppResult<Self> {
        let names: Vec<&'static str> = GovernedSecret::ALL
            .iter()
            .map(|secret| secret.name())
            .collect();
        // The table is application-scope (no RLS), so the migrator pool is
        // the right one to reach for: it has no tenant GUC to set and never
        // will. `db.pool()` here is the request-serving pool, which is
        // still fine because the table has no RLS policy that would refuse
        // it; using `db.pool()` avoids opening a second connection kind for
        // a single-row-per-secret read.
        // SAFETY (PMS-285): app-tier is not tenant scoped and the table
        // carries no RLS; there is no GUC to set.
        let rows: Vec<(String, Vec<u8>)> =
            sqlx::query_as("SELECT name, ciphertext FROM app_secrets WHERE name = ANY($1)")
                .bind(&names)
                .fetch_all(db.pool())
                .await
                .map_err(|e| AppError::Database(format!("could not preload app_secrets: {e}")))?;

        let mut loaded: HashMap<&'static str, String> = HashMap::new();
        for (row_name, ciphertext) in rows {
            let Some(&secret) = GovernedSecret::ALL
                .iter()
                .find(|s| s.name() == row_name.as_str())
            else {
                // Somebody wrote a name that is not a declared governed
                // secret. Not fatal: the boot only cares about declared
                // ones. Warn so the operator sees a stale row.
                tracing::warn!(
                    row_name = %row_name,
                    "app_secrets row {row_name:?} names no governed secret; ignored",
                );
                continue;
            };
            let ciphertext_str = match std::str::from_utf8(&ciphertext) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        secret = secret.name(),
                        error = %e,
                        "app_secrets ciphertext for {} is not utf-8; treating as unheld",
                        secret.name()
                    );
                    continue;
                }
            };
            match crypto::decrypt(ciphertext_str, &encryption_key) {
                Ok(plaintext) => {
                    if !plaintext.is_empty() {
                        loaded.insert(secret.name(), plaintext);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        secret = secret.name(),
                        error = %e,
                        "app_secrets ciphertext for {} does not decrypt under ENCRYPTION_KEY; \
                         treating as unheld",
                        secret.name()
                    );
                }
            }
        }
        Ok(Self {
            writer: WriteBackend::Real {
                db: db.clone(),
                key: encryption_key,
            },
            values: RwLock::new(loaded),
        })
    }
}

#[async_trait]
impl AppSecretProvider for DatabaseProvider {
    fn name(&self) -> &'static str {
        "database"
    }

    fn get(&self, secret: GovernedSecret) -> Option<String> {
        self.values
            .read()
            .expect("the app-tier database cache lock is never held across a panic")
            .get(secret.name())
            .cloned()
    }

    fn has(&self, secret: GovernedSecret) -> bool {
        // The value is small, but avoiding the clone in the survey is worth
        // one extra method definition: `has` is called for every provider by
        // every classification, `get` only for the one that serves.
        self.values
            .read()
            .expect("the app-tier database cache lock is never held across a panic")
            .contains_key(secret.name())
    }

    /// PMS-1012: encrypt `value`, upsert the `app_secrets` row, and store the
    /// plaintext in the in-memory cache so a read that follows the write sees
    /// it. The row and the cache are updated in the same call and the cache
    /// is only touched on a successful write, so a failing DB write leaves
    /// the previous value serving.
    async fn set(&self, secret: GovernedSecret, value: &str) -> AppResult<()> {
        let (db, key) = match &self.writer {
            WriteBackend::Real { db, key } => (db, key),
            #[cfg(test)]
            WriteBackend::Disabled => {
                return Err(AppError::Configuration(
                    "database provider was built without a pool; writes are disabled".to_string(),
                ));
            }
        };
        let ciphertext = crypto::encrypt(value, key)?;
        let ciphertext_bytes = ciphertext.as_bytes().to_vec();
        // SAFETY (PMS-285): app_secrets is application-scope and carries no
        // RLS; there is no tenant GUC to set. The migrator pool owns the
        // table (see migration 207) and is safe to use for the upsert.
        sqlx::query(
            r#"
            INSERT INTO app_secrets (name, ciphertext, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            ON CONFLICT (name) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = NOW()
            "#,
        )
        .bind(secret.name())
        .bind(&ciphertext_bytes)
        .execute(db.migrator_pool())
        .await
        .map_err(|e| AppError::Database(format!("could not write app_secrets row: {e}")))?;
        self.values
            .write()
            .expect("the app-tier database cache lock is never held across a panic")
            .insert(secret.name(), value.to_string());
        Ok(())
    }

    /// PMS-1012: delete the `app_secrets` row and drop the plaintext from the
    /// cache. A row that is already gone is not an error: the caller
    /// (`provider-purge`) has already checked the interlock and either the
    /// row was never there or another writer got to it first.
    async fn delete(&self, secret: GovernedSecret) -> AppResult<()> {
        let db = match &self.writer {
            WriteBackend::Real { db, .. } => db,
            #[cfg(test)]
            WriteBackend::Disabled => {
                return Err(AppError::Configuration(
                    "database provider was built without a pool; deletes are disabled".to_string(),
                ));
            }
        };
        sqlx::query("DELETE FROM app_secrets WHERE name = $1")
            .bind(secret.name())
            .execute(db.migrator_pool())
            .await
            .map_err(|e| AppError::Database(format!("could not delete app_secrets row: {e}")))?;
        self.values
            .write()
            .expect("the app-tier database cache lock is never held across a panic")
            .remove(secret.name());
        Ok(())
    }
}

impl DatabaseProvider {
    /// Test-only constructor: build a provider whose cache is populated but
    /// whose DB handle is never used. The trait's read paths hit the cache,
    /// so this is enough to exercise `get` and `has` without a real pool;
    /// `set` and `delete` refuse loudly, and are exercised behind an
    /// integration test that has a pool.
    #[cfg(test)]
    pub(crate) fn from_cache(values: HashMap<&'static str, String>) -> Self {
        Self {
            writer: WriteBackend::Disabled,
            values: RwLock::new(values),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cache with a value serves it; a cache without one is unheld. The
    /// serving/loading split lets the trait behaviour stay testable without
    /// a real postgres pool.
    #[test]
    fn cache_serves_the_loaded_value() {
        let provider = DatabaseProvider::from_cache(
            [(GovernedSecret::SmtpPassword.name(), "hunter2".to_string())]
                .into_iter()
                .collect(),
        );
        assert_eq!(
            provider.get(GovernedSecret::SmtpPassword),
            Some("hunter2".to_string())
        );
        assert!(provider.has(GovernedSecret::SmtpPassword));

        let empty = DatabaseProvider::from_cache(HashMap::new());
        assert!(!empty.has(GovernedSecret::SmtpPassword));
        assert_eq!(empty.get(GovernedSecret::SmtpPassword), None);
    }

    #[test]
    fn database_provider_is_writable_and_named() {
        let provider = DatabaseProvider::from_cache(HashMap::new());
        assert!(provider.is_writable());
        assert_eq!(provider.name(), "database");
    }
}
