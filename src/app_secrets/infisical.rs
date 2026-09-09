//! The Infisical provider: wraps [`crate::infisical::InfisicalClient`] and
//! reads governed secrets from a fixed folder.
//!
//! The client is the same one `crate::secrets::infisical` uses for the
//! tenant tier; only the folder differs (tenant tier writes under
//! `/mokosh/integrations`, this one under `/app`), so a deployment on
//! Infisical addresses tenant-scoped and application-scope secrets in the
//! same project without collision. The folder is CREATED by an operator
//! ahead of writes landing (PMS-1012); reads treat "the folder does not
//! exist yet" the same as "no value at this key", which is the Infisical
//! client's 404 = None contract.
//!
//! Every governed secret is fetched once at [`load`] and cached, for the
//! same reason [`crate::app_secrets::database`] preloads: the trait's `get`
//! is sync, and hitting the network on every classification round would
//! turn each `has` into a live call.

use std::collections::HashMap;

use super::{AppSecretProvider, GovernedSecret};
use crate::infisical::InfisicalClient;
use crate::secrets::infisical::InfisicalSecretsConfig;
use crate::utils::error::AppResult;

/// The folder governed application-tier secrets live in.
///
/// Fixed rather than configurable: an Infisical folder is not the sort of
/// thing a deployment gains a benefit from renaming, and a config toggle
/// here would be one more place a deployment could drift.
const APP_SECRET_PATH: &str = "/app";

/// The Infisical-backed application-tier secret provider.
pub struct InfisicalProvider {
    values: HashMap<&'static str, String>,
}

impl InfisicalProvider {
    /// Build the client from environment, then fetch every governed secret
    /// once and cache the results.
    ///
    /// The env-var reading lives in `crate::secrets::infisical`'s
    /// [`InfisicalSecretsConfig::from_env`] (the tenant tier's entry
    /// point). Reusing it means the same variables that already reach the
    /// tenant provider reach this one: `INFISICAL_ADDRESS`,
    /// `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`,
    /// `INFISICAL_CLIENT_SECRET`, `INFISICAL_ENVIRONMENT`.
    ///
    /// A network failure here is a fatal boot error: the operator declared
    /// Infisical's inputs by setting `INFISICAL_ADDRESS`, and a silent
    /// "provider builds but is empty" would be exactly the shape the boot
    /// classification exists to catch. A missing secret in Infisical is a
    /// different fact (returned as `None` by the client on 404), and is
    /// treated as unheld in the cache.
    pub async fn load() -> AppResult<Self> {
        let config = InfisicalSecretsConfig::from_env()?;
        let client =
            InfisicalClient::connect(&config.address, &config.client_id, &config.client_secret)?;

        let mut values: HashMap<&'static str, String> = HashMap::new();
        for secret in GovernedSecret::ALL {
            let value = client
                .get_secret(
                    &config.project_id,
                    &config.environment,
                    APP_SECRET_PATH,
                    secret.name(),
                )
                .await?;
            if let Some(v) = value.filter(|s| !s.is_empty()) {
                values.insert(secret.name(), v);
            }
        }

        Ok(Self { values })
    }
}

impl AppSecretProvider for InfisicalProvider {
    fn name(&self) -> &'static str {
        "infisical"
    }

    fn get(&self, secret: GovernedSecret) -> Option<String> {
        self.values.get(secret.name()).cloned()
    }

    fn has(&self, secret: GovernedSecret) -> bool {
        self.values.contains_key(secret.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cache-shaped side of the provider is testable without the
    /// network: the trait's methods read the map that `load` populated, so
    /// we exercise them directly.
    #[test]
    fn cache_serves_the_loaded_value() {
        let provider = InfisicalProvider {
            values: [(GovernedSecret::SmtpPassword.name(), "hunter2".to_string())]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            provider.get(GovernedSecret::SmtpPassword),
            Some("hunter2".to_string())
        );
        assert!(provider.has(GovernedSecret::SmtpPassword));
    }

    #[test]
    fn infisical_provider_is_writable_and_named() {
        let provider = InfisicalProvider {
            values: HashMap::new(),
        };
        assert!(provider.is_writable());
        assert_eq!(provider.name(), "infisical");
    }
}
