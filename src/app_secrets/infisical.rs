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
use std::sync::RwLock;

use async_trait::async_trait;

use super::{AppSecretProvider, GovernedSecret};
use crate::infisical::InfisicalClient;
use crate::secrets::infisical::InfisicalSecretsConfig;
#[cfg(test)]
use crate::utils::error::AppError;
use crate::utils::error::AppResult;

/// The folder governed application-tier secrets live in.
///
/// Fixed rather than configurable: an Infisical folder is not the sort of
/// thing a deployment gains a benefit from renaming, and a config toggle
/// here would be one more place a deployment could drift.
const APP_SECRET_PATH: &str = "/app";

/// The Infisical-backed application-tier secret provider.
pub struct InfisicalProvider {
    connection: ConnectionBackend,
    values: RwLock<HashMap<&'static str, String>>,
}

/// The client half of the provider, split from the cache so unit tests can
/// build the cache without talking to Infisical.
enum ConnectionBackend {
    /// The real backend: an Infisical HTTP client, plus the workspace,
    /// environment slug and folder path every secret call needs.
    Real {
        client: InfisicalClient,
        project_id: String,
        environment: String,
    },
    /// A test-only sentinel; every `set`/`delete` refuses so unit tests that
    /// only exercise the read path stay network-free.
    #[cfg(test)]
    Disabled,
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

        Ok(Self {
            connection: ConnectionBackend::Real {
                client,
                project_id: config.project_id,
                environment: config.environment,
            },
            values: RwLock::new(values),
        })
    }
}

#[async_trait]
impl AppSecretProvider for InfisicalProvider {
    fn name(&self) -> &'static str {
        "infisical"
    }

    fn get(&self, secret: GovernedSecret) -> Option<String> {
        self.values
            .read()
            .expect("the app-tier infisical cache lock is never held across a panic")
            .get(secret.name())
            .cloned()
    }

    fn has(&self, secret: GovernedSecret) -> bool {
        self.values
            .read()
            .expect("the app-tier infisical cache lock is never held across a panic")
            .contains_key(secret.name())
    }

    /// PMS-1012: write the value into Infisical's application folder and
    /// update the cache in one call, so a read that follows the write sees
    /// it. The cache is only touched on a successful upstream write.
    async fn set(&self, secret: GovernedSecret, value: &str) -> AppResult<()> {
        let (client, project_id, environment) = match &self.connection {
            ConnectionBackend::Real {
                client,
                project_id,
                environment,
            } => (client, project_id.as_str(), environment.as_str()),
            #[cfg(test)]
            ConnectionBackend::Disabled => {
                return Err(AppError::Configuration(
                    "infisical provider was built without a client; writes are disabled"
                        .to_string(),
                ));
            }
        };
        client
            .put_secret(
                project_id,
                environment,
                APP_SECRET_PATH,
                secret.name(),
                value,
            )
            .await?;
        self.values
            .write()
            .expect("the app-tier infisical cache lock is never held across a panic")
            .insert(secret.name(), value.to_string());
        Ok(())
    }

    /// PMS-1012: remove the secret from Infisical's application folder and
    /// drop it from the cache. Absence is not an error, matching
    /// [`InfisicalClient::delete_secret`]'s contract.
    async fn delete(&self, secret: GovernedSecret) -> AppResult<()> {
        let (client, project_id, environment) = match &self.connection {
            ConnectionBackend::Real {
                client,
                project_id,
                environment,
            } => (client, project_id.as_str(), environment.as_str()),
            #[cfg(test)]
            ConnectionBackend::Disabled => {
                return Err(AppError::Configuration(
                    "infisical provider was built without a client; deletes are disabled"
                        .to_string(),
                ));
            }
        };
        client
            .delete_secret(project_id, environment, APP_SECRET_PATH, secret.name())
            .await?;
        self.values
            .write()
            .expect("the app-tier infisical cache lock is never held across a panic")
            .remove(secret.name());
        Ok(())
    }
}

impl InfisicalProvider {
    /// Test-only constructor: build a provider whose cache is populated but
    /// whose client is disabled. The trait's read paths hit the cache, so
    /// this is enough to exercise `get` and `has` without the network.
    #[cfg(test)]
    pub(crate) fn from_cache(values: HashMap<&'static str, String>) -> Self {
        Self {
            connection: ConnectionBackend::Disabled,
            values: RwLock::new(values),
        }
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
        let provider = InfisicalProvider::from_cache(
            [(GovernedSecret::SmtpPassword.name(), "hunter2".to_string())]
                .into_iter()
                .collect(),
        );
        assert_eq!(
            provider.get(GovernedSecret::SmtpPassword),
            Some("hunter2".to_string())
        );
        assert!(provider.has(GovernedSecret::SmtpPassword));
    }

    #[test]
    fn infisical_provider_is_writable_and_named() {
        let provider = InfisicalProvider::from_cache(HashMap::new());
        assert!(provider.is_writable());
        assert_eq!(provider.name(), "infisical");
    }
}
