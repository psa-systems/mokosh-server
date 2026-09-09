//! The database configuration provider (PMS-987): read declared keys out of
//! the `app_config` table (migration 210).
//!
//! `app_config` is one row per key (`name` PRIMARY KEY), the value stored
//! in plaintext because this is configuration, not secrets. The encrypted
//! sibling is `app_secrets` (PMS-988), which serves `SecretProvider`. The
//! split is deliberate: an SMTP HOST goes here (a compromised row dump is
//! not a leak worth encrypting against), an SMTP PASSWORD goes over there
//! (a compromised row dump without `ENCRYPTION_KEY` is unusable).
//!
//! # Bootstrap-tier refusal
//!
//! The database provider CANNOT serve a bootstrap-tier key. The reason
//! `docs/providers.md` gives: the database cannot hold the credential used
//! to reach the database, and the encryption key that would protect any
//! ciphertext here would have to reach the pool before the pool could be
//! opened. That is a deadlock at boot.
//!
//! Two guards enforce it:
//! - [`DatabaseProvider::build`] takes the exact keys it will be asked for
//!   and returns an error naming any bootstrap-tier entry, so wiring the
//!   provider up for a bootstrap key is a boot failure and not a runtime
//!   surprise.
//! - The cache holds only the app-tier keys `build` was given, so a
//!   bootstrap-tier lookup at [`ConfigProvider::get`] time cannot succeed
//!   even if the guard is somehow reached with one.
//!
//! # Load-once
//!
//! Like `AppSecretsDatabaseProvider` (PMS-988), every application-tier key
//! is preloaded at construction and cached in a `HashMap`. The trait's
//! `get` is sync, so a blocking DB call from every read path would either
//! deadlock the runtime or force every caller onto the blocking pool. A
//! save through this provider therefore requires a chain rebuild for this
//! process to see it, which is what the migrate CLI (PMS-1012) will drive.

use std::collections::HashMap;

use super::{ConfigKey, ConfigProvider, Enumeration, Tier};
use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

/// The database-backed configuration provider. Populated once by
/// [`DatabaseProvider::build`]; never mutated afterwards.
pub struct DatabaseProvider {
    values: HashMap<String, String>,
}

impl DatabaseProvider {
    /// Build the provider by preloading every key in `keys` from
    /// `app_config`. Refuses any bootstrap-tier key naming it, before
    /// touching the pool: an operator who wired the DB provider up for a
    /// bootstrap key gets a startup error, never a boot that fails midway.
    pub async fn build(db: &Database, keys: &[&'static ConfigKey]) -> AppResult<Self> {
        refuse_bootstrap(keys)?;

        let names: Vec<&'static str> = keys.iter().map(|k| k.name()).collect();
        if names.is_empty() {
            return Ok(Self {
                values: HashMap::new(),
            });
        }

        // SAFETY (PMS-285): app_config is application-scope and carries no
        // RLS policy; there is no tenant GUC to set. `db.pool()` is the
        // request-serving `mokosh_app` pool, which has SELECT on the table
        // per migration 210.
        let rows: Vec<(String, String)> = sqlx::query_as::<_, (String, String)>(
            "SELECT name, value FROM app_config WHERE name = ANY($1)",
        )
        .bind(&names)
        .fetch_all(db.pool())
        .await
        .map_err(|e| AppError::Database(format!("could not preload app_config: {e}")))?;

        let values: HashMap<String, String> = rows
            .into_iter()
            .filter(|(name, _)| names.contains(&name.as_str()))
            .collect();

        Ok(Self { values })
    }

    /// Build from an already-materialised map. Kept crate-visible so tests
    /// can drive the trait without a live pool.
    #[cfg(test)]
    pub(crate) fn from_map(values: HashMap<String, String>) -> Self {
        Self { values }
    }
}

/// Refuse any bootstrap-tier entry in `keys`, listing all offenders.
///
/// Pure function split out from [`DatabaseProvider::build`] so it is
/// testable without a pool and so the check runs BEFORE any I/O.
pub(crate) fn refuse_bootstrap(keys: &[&'static ConfigKey]) -> AppResult<()> {
    let denied: Vec<&'static str> = keys
        .iter()
        .filter(|k| k.tier() == Tier::Bootstrap)
        .map(|k| k.name())
        .collect();
    if denied.is_empty() {
        Ok(())
    } else {
        Err(AppError::Configuration(format!(
            "the database configuration provider cannot serve bootstrap-tier keys \
             (the credential used to reach the database cannot come from the \
             database): {}",
            denied.join(", ")
        )))
    }
}

impl ConfigProvider for DatabaseProvider {
    fn name(&self) -> &'static str {
        "database"
    }

    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }

    fn has(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    fn list(&self) -> Enumeration {
        Enumeration::Keys(self.values.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::registry;

    #[test]
    fn the_provider_names_itself_as_database() {
        let provider = DatabaseProvider::from_map(HashMap::new());
        assert_eq!(provider.name(), "database");
    }

    #[test]
    fn build_refuses_a_bootstrap_key_naming_it() {
        // Every declared bootstrap key must be refused, and the message must
        // name the key so an operator's log line is enough to fix it.
        for key in registry::REGISTRY {
            if key.tier() != Tier::Bootstrap {
                continue;
            }
            let err = refuse_bootstrap(&[key])
                .expect_err("a bootstrap key must not build into the DB provider");
            let msg = err.to_string();
            assert!(msg.contains(key.name()), "{}: {msg}", key.name());
            assert!(msg.contains("bootstrap"), "the message must say why: {msg}");
        }
    }

    #[test]
    fn build_accepts_only_application_tier_keys() {
        let app: Vec<&'static ConfigKey> = registry::REGISTRY
            .iter()
            .copied()
            .filter(|k| k.tier() == Tier::Application)
            .collect();
        refuse_bootstrap(&app).expect("application-tier keys are accepted");
    }

    #[test]
    fn a_bootstrap_key_lookup_reads_as_unheld_from_the_cache() {
        // The cache holds only what the caller loaded. A caller that did NOT
        // load a bootstrap key sees `None` regardless of what is in the
        // process environment, so a chain that put the DB provider ahead of
        // the environment for a bootstrap key would still resolve it out
        // of the environment (the classification then reports the misplacement).
        let provider = DatabaseProvider::from_map(HashMap::new());
        assert_eq!(provider.get("DATABASE_URL"), None);
        assert!(!provider.has("DATABASE_URL"));
    }

    #[test]
    fn a_cached_value_serves() {
        let mut values = HashMap::new();
        values.insert("SMTP_HOST".to_string(), "relay.example.com".to_string());
        let provider = DatabaseProvider::from_map(values);
        assert_eq!(
            provider.get("SMTP_HOST").as_deref(),
            Some("relay.example.com")
        );
        assert!(provider.has("SMTP_HOST"));
        match provider.list() {
            Enumeration::Keys(keys) => assert_eq!(keys, vec!["SMTP_HOST".to_string()]),
            Enumeration::Unsupported => panic!("the DB provider can enumerate"),
        }
    }
}
