//! The Infisical provider, selected by `SECRET_BACKEND=infisical`.
//!
//! Writes into `/mokosh/integrations`, one of the three folders the first-run
//! bootstrap already creates and grants the Universal Auth machine identity
//! secret-write on. That folder's own comment in `infisical/bootstrap.rs` calls
//! it a folder "the runtime needs to write secrets into"; until PMS-967 no
//! runtime code ever did.
//!
//! Read [`crate::secrets`] for the outage decision this implements. In short: a
//! read-through TTL cache, and a hard failure on a miss rather than a fallback,
//! because a fallback means quietly not using the provider the operator chose.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{SecretKey, SecretProvider};
use crate::infisical::InfisicalClient;
use crate::utils::error::{AppError, AppResult};

/// The folder the bootstrap pre-creates for integration credentials.
const SECRET_PATH: &str = "/mokosh/integrations";

/// How long a read stays cached.
///
/// A secret changes when an operator reconnects an integration, which is rare,
/// so this is not a staleness/performance trade so much as an availability one:
/// it is how long a running deployment keeps working through an Infisical
/// outage. Five minutes is short enough that a rotated credential takes effect
/// without a restart, and long enough that a brief outage is invisible.
const CACHE_TTL: Duration = Duration::from_secs(300);

struct CachedSecret {
    /// `None` is cached too: a tenant with no integration configured would
    /// otherwise reach the network on every request that checks.
    value: Option<String>,
    stored_at: Instant,
}

/// Where the Infisical project lives. Read once at construction rather than per
/// call, so a half-configured deployment fails at startup and not at the moment
/// a customer tries to pay.
#[derive(Clone, Debug)]
pub struct InfisicalSecretsConfig {
    pub address: String,
    pub project_id: String,
    pub environment: String,
    pub client_id: String,
    pub client_secret: String,
}

impl InfisicalSecretsConfig {
    /// Read the Universal Auth settings the dev compose file has always
    /// forwarded to the server and nothing has ever read.
    ///
    /// Every value is required, and a blank one counts as missing: a forwarded
    /// but unset variable arrives as `""` (PMS-836), so treating empty as
    /// present would produce an authentication failure at first use instead of
    /// a clear error at boot.
    pub fn from_env() -> AppResult<Self> {
        fn required(name: &str) -> AppResult<String> {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    AppError::Configuration(format!(
                        "SECRET_BACKEND=infisical requires {name} to be set"
                    ))
                })
        }
        Ok(Self {
            address: required("INFISICAL_ADDRESS")?,
            project_id: required("INFISICAL_PROJECT_ID")?,
            environment: std::env::var("INFISICAL_ENVIRONMENT")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "dev".to_string()),
            client_id: required("INFISICAL_CLIENT_ID")?,
            client_secret: required("INFISICAL_CLIENT_SECRET")?,
        })
    }
}

pub struct InfisicalSecretProvider {
    client: Arc<InfisicalClient>,
    project_id: String,
    environment: String,
    cache: Arc<RwLock<HashMap<String, CachedSecret>>>,
    ttl: Duration,
}

impl InfisicalSecretProvider {
    pub fn new(config: InfisicalSecretsConfig) -> AppResult<Self> {
        let client =
            InfisicalClient::connect(&config.address, &config.client_id, &config.client_secret)?;
        Ok(Self {
            client: Arc::new(client),
            project_id: config.project_id,
            environment: config.environment,
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl: CACHE_TTL,
        })
    }

    pub fn from_env() -> AppResult<Self> {
        Self::new(InfisicalSecretsConfig::from_env()?)
    }

    /// Drop a cached entry so the next read goes to Infisical.
    ///
    /// Called after every write rather than updating the entry in place: a
    /// write that Infisical accepted and this process misrecorded would serve a
    /// value nobody stored, and re-reading costs one request on a path that
    /// happens when an operator saves a form.
    async fn invalidate(&self, name: &str) {
        self.cache.write().await.remove(name);
    }
}

#[async_trait]
impl SecretProvider for InfisicalSecretProvider {
    async fn get(&self, key: &SecretKey) -> AppResult<Option<String>> {
        let name = key.name()?;

        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&name) {
                if entry.stored_at.elapsed() < self.ttl {
                    return Ok(entry.value.clone());
                }
            }
        }

        // A miss during an outage is an error and never `None`. `None` means
        // "this tenant has not configured it", and collapsing the two would
        // turn an Infisical outage into every integration silently switching
        // itself off, which is the failure this module exists to refuse.
        let value = self
            .client
            .get_secret(&self.project_id, &self.environment, SECRET_PATH, &name)
            .await?;

        self.cache.write().await.insert(
            name,
            CachedSecret {
                value: value.clone(),
                stored_at: Instant::now(),
            },
        );
        Ok(value)
    }

    async fn put(&self, key: &SecretKey, value: &str) -> AppResult<()> {
        let name = key.name()?;
        self.client
            .put_secret(
                &self.project_id,
                &self.environment,
                SECRET_PATH,
                &name,
                value,
            )
            .await?;
        self.invalidate(&name).await;
        Ok(())
    }

    async fn delete(&self, key: &SecretKey) -> AppResult<()> {
        let name = key.name()?;
        self.client
            .delete_secret(&self.project_id, &self.environment, SECRET_PATH, &name)
            .await?;
        self.invalidate(&name).await;
        Ok(())
    }
}
