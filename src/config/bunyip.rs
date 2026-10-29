//! The Bunyip configuration provider (PMS-987, corrected by PMS-1553): read
//! the suite facts bunyip holds from its host-config route.
//!
//! ## What was wrong with it
//!
//! PMS-987 shipped this provider against two endpoints bunyip does not serve.
//! It exchanged the machine credential at `POST /v1/oauth2/token` for a bearer
//! and then read `GET /v1/config/{KEY}`: bunyip's token endpoint is root-level
//! and implements `authorization_code` and `refresh_token` only, so it mints
//! nothing for a machine, and there was no `/v1/config` route at all. The
//! provider could not have resolved a key against a real bunyip, and nothing
//! noticed because no boot path can select it (`CONFIG_BACKEND` takes
//! `environment` alone, and `CONFIG_PROVIDERS` is read by the provider CLI).
//!
//! BUNYIP-1011 shipped the route it needed, so this now reads
//! `GET /v1/host/config/{KEY}` with the machine credential as HTTP Basic,
//! which is how every machine endpoint over there authenticates.
//!
//! ## One key, not every key
//!
//! The old loop asked bunyip for every declared key in the registry, which is
//! over a hundred requests per build and more than bunyip's own per-app cap
//! allows in a minute. bunyip serves the facts it OWNS, so this provider
//! carries the mapping from a Mokosh key to bunyip's namespaced one and asks
//! only for those. One today: `ABUSE_CONTACT_EMAIL`, which is bunyip's
//! monitored support mailbox (`mokosh/abuse_contact_email`), and which a
//! deployment otherwise keeps in step with bunyip's own setting by hand.
//!
//! ## What a failure means
//!
//! A refused CREDENTIAL (401) or a refused KEY (403) is a hard error: the
//! provider cannot serve anything, and the remedy is in bunyip, so saying so
//! beats reporting the key as unheld. A 404 or a transport failure on one key
//! leaves that key unheld and logs it, because the provider itself is working
//! and the next key may be fine. That is the same distinction the app-secret
//! tier draws between a provider that could not be built and one that holds
//! nothing (PMS-1537).
//!
//! `BUNYIP_CONFIG_URL` unset builds an empty provider silently, the way an
//! absent `CONFIG_FILE_DIR` builds the file provider empty: this is
//! ENABLEMENT, not misconfiguration. All three inputs live under
//! `ConfigKey::Bootstrap` because this provider is BUILT from them.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;

use super::{ConfigProvider, Enumeration};
use crate::utils::error::{AppError, AppResult};

/// bunyip's host-config route (BUNYIP-1011). Not `/v1/config/`, which does
/// not exist there, and not under `/v1/oauth2/` either: there is no token to
/// exchange, because bunyip mints no bearer for a machine caller.
const HOST_CONFIG_PREFIX: &str = "/v1/host/config/";

/// The keys bunyip serves, as `(this registry's name, bunyip's key)`.
///
/// A mapping rather than the whole registry: bunyip serves the facts it owns,
/// and asking it for all hundred-odd declared keys would be a hundred requests
/// per build and an instant 429 against its per-app cap. A key bunyip starts
/// serving joins this list, and its `--config-key` goes on the deployment's
/// registration over there.
const SERVED_KEYS: &[(&str, &str)] = &[("ABUSE_CONTACT_EMAIL", "mokosh/abuse_contact_email")];
/// Bunyip's per-request budget. Sized like the PayPal token call and long
/// enough that a slow probe does not silently swallow a real timeout.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Machine-credential inputs the Bunyip provider is BUILT from. Kept as a
/// small struct so the parsing rules stay in one place and a test can drive
/// [`BunyipProvider::load`] without touching the process environment.
#[derive(Debug, Clone)]
pub struct BunyipConfig {
    /// Base URL (no trailing slash) of the Bunyip API.
    pub base_url: String,
    pub client_id: String,
    pub client_secret: String,
}

impl BunyipConfig {
    /// Read all three inputs. Returns `Ok(None)` when the URL is unset:
    /// the provider stays enabled-but-empty, exactly the same shape as an
    /// absent `CONFIG_FILE_DIR`.
    ///
    /// Direct env reads (not through [`crate::config::get`]) because the
    /// three variables are construction inputs for THIS provider; see
    /// `src/config/guard.rs` for the exemption.
    pub fn from_env() -> AppResult<Option<Self>> {
        let base = std::env::var("BUNYIP_CONFIG_URL")
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty());
        let Some(base) = base else {
            return Ok(None);
        };
        let client_id = required("BUNYIP_CONFIG_CLIENT_ID")?;
        let client_secret = required("BUNYIP_CONFIG_CLIENT_SECRET")?;
        Ok(Some(Self {
            base_url: base.trim_end_matches('/').to_string(),
            client_id,
            client_secret,
        }))
    }
}

/// A credential half, read file-first: `{NAME}_FILE` is the compose-secret
/// form, because a plain value in a compose `environment:` block is visible to
/// `docker inspect` and to every child process (PMS-1537 reads the host-secret
/// credential the same way).
fn required(name: &'static str) -> AppResult<String> {
    let from_file = std::env::var(format!("{name}_FILE"))
        .ok()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .and_then(|path| match std::fs::read_to_string(&path) {
            Ok(contents) => Some(contents.trim().to_string()),
            Err(e) => {
                tracing::error!(
                    file = %path,
                    error = %e,
                    "{name}_FILE points at an unreadable file, so the bunyip configuration \
                     provider has no credential from it"
                );
                None
            }
        })
        .filter(|value| !value.is_empty());
    if let Some(value) = from_file {
        return Ok(value);
    }
    match std::env::var(name).ok().map(|s| s.trim().to_string()) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(AppError::Configuration(format!(
            "BUNYIP_CONFIG_URL is set, so {name} must be set too; the Bunyip \
             configuration provider needs both halves of its machine \
             credential"
        ))),
    }
}

/// The Bunyip-backed configuration provider. Populated once by
/// [`BunyipProvider::from_env`] / [`BunyipProvider::load`]; never mutated.
pub struct BunyipProvider {
    values: BTreeMap<String, String>,
}

/// Hand-written rather than derived: these are not secrets, but a provider
/// that prints its contents into a panic message is a habit worth not having,
/// and the useful fact in a diagnostic is how many keys it resolved.
impl std::fmt::Debug for BunyipProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BunyipProvider")
            .field("keys_held", &self.values.len())
            .finish()
    }
}

impl BunyipProvider {
    /// Read [`BunyipConfig::from_env`] and, when a URL is configured,
    /// authenticate and fetch every declared key. Unset URL yields an empty
    /// provider that has issued no request.
    pub async fn from_env() -> AppResult<Self> {
        match BunyipConfig::from_env()? {
            Some(config) => Self::load(&config).await,
            None => Ok(Self {
                values: BTreeMap::new(),
            }),
        }
    }

    /// Build against an explicit [`BunyipConfig`]. Public so a test can drive
    /// the network path against a stub base URL.
    pub async fn load(config: &BunyipConfig) -> AppResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| {
                AppError::external_service("bunyip-config", format!("http client build: {e}"))
            })?;

        let mut values = BTreeMap::new();
        for (local, remote) in SERVED_KEYS {
            match fetch_value(&http, config, remote).await {
                Ok(Some(value)) => {
                    values.insert((*local).to_string(), value);
                }
                Ok(None) => {
                    // 404: bunyip serves this key but holds no value for it,
                    // which is a fact about bunyip's own configuration and
                    // leaves the key unheld here.
                    tracing::info!(
                        key = *local,
                        bunyip_key = *remote,
                        "bunyip holds no value for {remote}; {local} stays unheld"
                    );
                }
                // A refused credential or a refused key is the provider
                // failing, not one value missing, so it stops the build with
                // the remedy named.
                Err(err) => return Err(err),
            }
        }

        Ok(Self { values })
    }
}

#[async_trait]
impl ConfigProvider for BunyipProvider {
    fn name(&self) -> &'static str {
        "bunyip"
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

    /// Bunyip's `PUT /v1/config/{KEY}` is a follow-up ticket; today the
    /// Bunyip provider stays read-only, so an operator asking to migrate
    /// TO it gets a named refusal rather than a silent success.
    async fn set(&self, _key: &str, _value: &str) -> AppResult<()> {
        Err(AppError::Configuration(
            "bunyip provider write is not implemented".to_string(),
        ))
    }
}

/// One key, read with the machine credential as HTTP Basic.
///
/// `Ok(None)` only for a 404, which is bunyip saying it holds no value for a
/// key it does serve. A refused credential and a refused key are errors
/// naming their own remedy, because they are fixed in bunyip and in two
/// different places.
async fn fetch_value(
    http: &reqwest::Client,
    config: &BunyipConfig,
    key: &str,
) -> AppResult<Option<String>> {
    let url = format!("{}{HOST_CONFIG_PREFIX}{key}", config.base_url);
    let resp = http
        .get(&url)
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            AppError::external_service(
                "bunyip-config",
                format!(
                    "could not reach bunyip at {url}: {e}. Check BUNYIP_CONFIG_URL and that \
                     bunyip is reachable from this host."
                ),
            )
        })?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(AppError::external_service(
            "bunyip-config",
            "bunyip refused this deployment's configuration credential (401). The registration \
             named by BUNYIP_CONFIG_CLIENT_ID is unknown, disabled or holds a different secret; \
             rotate it with `bunyip-api machine-client rotate --client-id <id>`."
                .to_string(),
        ));
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        return Err(AppError::external_service(
            "bunyip-config",
            format!(
                "bunyip serves {key} but this registration may not read it (403). Add it to the \
                 registration's allow-list: `bunyip-api machine-client register --name \
                 mokosh-host-config --config-key {key}`. A host-SECRETS credential does not \
                 carry configuration keys (BUNYIP-855 D9), so check which registration \
                 BUNYIP_CONFIG_CLIENT_ID names."
            ),
        ));
    }
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::external_service(
            "bunyip-config",
            format!("bunyip answered {status} for {key}: {text}"),
        ));
    }

    // bunyip's envelope: `{"data": {"key": "...", "value": "..."}}`. Read
    // through the shape rather than guessing, since guessing is what left the
    // old implementation accepting three shapes and matching none of them.
    let envelope: serde_json::Value = resp.json().await.map_err(|e| {
        AppError::external_service(
            "bunyip-config",
            format!("bunyip's answer for {key} was not the expected envelope: {e}"),
        )
    })?;
    Ok(envelope["data"]["value"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// The provider names itself as `bunyip`, matching the operator
    /// vocabulary in `.env.example` and the `SECRET_BACKEND` shape.
    #[test]
    fn the_provider_names_itself_as_bunyip() {
        let provider = BunyipProvider {
            values: BTreeMap::new(),
        };
        assert_eq!(provider.name(), "bunyip");
    }

    /// A blank / unset URL builds no config: `from_env` returns `Ok(None)`
    /// and callers construct an empty provider that never issues a request.
    #[test]
    fn a_blank_url_yields_no_config() {
        // Serialise env mutation: tests in this crate write process-global
        // env and would race otherwise.
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("BUNYIP_CONFIG_URL");
        std::env::remove_var("BUNYIP_CONFIG_CLIENT_ID");
        std::env::remove_var("BUNYIP_CONFIG_CLIENT_SECRET");
        assert!(BunyipConfig::from_env().unwrap().is_none());
        std::env::set_var("BUNYIP_CONFIG_URL", "   ");
        assert!(BunyipConfig::from_env().unwrap().is_none());
        std::env::remove_var("BUNYIP_CONFIG_URL");
    }

    #[test]
    fn a_url_without_a_client_credential_is_a_configuration_error() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("BUNYIP_CONFIG_URL", "https://api.example.com");
        std::env::remove_var("BUNYIP_CONFIG_CLIENT_ID");
        std::env::remove_var("BUNYIP_CONFIG_CLIENT_SECRET");

        let err = BunyipConfig::from_env().expect_err("credential is required");
        let msg = err.to_string();
        assert!(msg.contains("BUNYIP_CONFIG_CLIENT_ID"), "{msg}");

        std::env::set_var("BUNYIP_CONFIG_CLIENT_ID", "abc");
        let err = BunyipConfig::from_env().expect_err("secret is still required");
        let msg = err.to_string();
        assert!(msg.contains("BUNYIP_CONFIG_CLIENT_SECRET"), "{msg}");

        std::env::remove_var("BUNYIP_CONFIG_URL");
        std::env::remove_var("BUNYIP_CONFIG_CLIENT_ID");
    }

    #[test]
    fn a_configured_url_trims_a_trailing_slash() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("BUNYIP_CONFIG_URL", "https://api.example.com/");
        std::env::set_var("BUNYIP_CONFIG_CLIENT_ID", "id");
        std::env::set_var("BUNYIP_CONFIG_CLIENT_SECRET", "secret");
        let cfg = BunyipConfig::from_env().unwrap().unwrap();
        assert_eq!(cfg.base_url, "https://api.example.com");
        std::env::remove_var("BUNYIP_CONFIG_URL");
        std::env::remove_var("BUNYIP_CONFIG_CLIENT_ID");
        std::env::remove_var("BUNYIP_CONFIG_CLIENT_SECRET");
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }
}
