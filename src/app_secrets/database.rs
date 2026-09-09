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

use super::{AppSecretProvider, GovernedSecret};
use crate::db::Database;
use crate::utils::crypto;
use crate::utils::error::{AppError, AppResult};

/// The database-backed application-tier secret provider.
///
/// The cache is populated once by [`DatabaseProvider::load`] and never
/// mutated afterwards; a value written elsewhere reaches this process on the
/// next process boot (or the next `init_from_env` invocation from an admin
/// live-reload path, which will land with the CLI in PMS-1012).
pub struct DatabaseProvider {
    values: HashMap<&'static str, String>,
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

        let mut values: HashMap<&'static str, String> = HashMap::new();
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
                        values.insert(secret.name(), plaintext);
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
        Ok(Self { values })
    }
}

impl AppSecretProvider for DatabaseProvider {
    fn name(&self) -> &'static str {
        "database"
    }

    fn get(&self, secret: GovernedSecret) -> Option<String> {
        self.values.get(secret.name()).cloned()
    }

    fn has(&self, secret: GovernedSecret) -> bool {
        // The value is small, but avoiding the clone in the survey is worth
        // one extra method definition: `has` is called for every provider by
        // every classification, `get` only for the one that serves.
        self.values.contains_key(secret.name())
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
        let provider = DatabaseProvider {
            values: [(GovernedSecret::SmtpPassword.name(), "hunter2".to_string())]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            provider.get(GovernedSecret::SmtpPassword),
            Some("hunter2".to_string())
        );
        assert!(provider.has(GovernedSecret::SmtpPassword));

        let empty = DatabaseProvider {
            values: HashMap::new(),
        };
        assert!(!empty.has(GovernedSecret::SmtpPassword));
        assert_eq!(empty.get(GovernedSecret::SmtpPassword), None);
    }

    #[test]
    fn database_provider_is_writable_and_named() {
        let provider = DatabaseProvider {
            values: HashMap::new(),
        };
        assert!(provider.is_writable());
        assert_eq!(provider.name(), "database");
    }
}
