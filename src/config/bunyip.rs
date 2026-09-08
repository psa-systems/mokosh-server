//! The Bunyip configuration provider (PMS-987): read declared keys from
//! Bunyip's `/v1/config` API, authenticated as a machine client.
//!
//! Bunyip authenticates the caller as a service via `POST /v1/oauth2/token`
//! with a `client_credentials` grant. This provider follows the same shape
//! the PayPal integration uses (`modules/billing/provider/paypal.rs`): the
//! client id and secret are HTTP Basic on the token request, the returned
//! bearer is presented on subsequent reads. That endpoint (`/v1/config/{KEY}`)
//! may not exist upstream yet: the ticket ships the seam, and the failure
//! shape when it does not answer is exactly the shape it will when a specific
//! key is not held there.
//!
//! `BUNYIP_CONFIG_URL` unset builds an empty provider silently, the way an
//! absent `CONFIG_FILE_DIR` builds the file provider empty: this is
//! ENABLEMENT, not misconfiguration. When set, [`from_env`] performs the
//! token exchange and then one GET per declared key. All three inputs
//! (URL, client id, client secret) live under `ConfigKey::Bootstrap`
//! because this provider is BUILT from them.

use std::collections::BTreeMap;
use std::time::Duration;

use super::{ConfigProvider, Enumeration, REGISTRY};
use crate::utils::error::{AppError, AppResult};

const TOKEN_PATH: &str = "/v1/oauth2/token";
const CONFIG_PATH_PREFIX: &str = "/v1/config/";
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

fn required(name: &'static str) -> AppResult<String> {
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

        let token = fetch_access_token(&http, config).await?;

        let mut values = BTreeMap::new();
        for key in REGISTRY {
            match fetch_value(&http, config, &token, key.name()).await {
                Ok(Some(value)) => {
                    values.insert(key.name().to_string(), value);
                }
                Ok(None) => {
                    // 404 = "Bunyip does not hold this key".
                }
                Err(err) => {
                    // A network failure on ONE key must not blank the whole
                    // provider. The value stays unheld for classification.
                    // The KEY is named, never the value.
                    tracing::error!(
                        key = key.name(),
                        error = %err,
                        "Bunyip configuration provider could not read {}; treating it as unheld",
                        key.name()
                    );
                }
            }
        }

        Ok(Self { values })
    }
}

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
}

async fn fetch_access_token(http: &reqwest::Client, config: &BunyipConfig) -> AppResult<String> {
    let url = format!("{}{TOKEN_PATH}", config.base_url);
    let resp = http
        .post(&url)
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .map_err(|e| AppError::external_service("bunyip-config", format!("token request: {e}")))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.map_err(|e| {
        AppError::external_service("bunyip-config", format!("token body not json: {e}"))
    })?;
    if !status.is_success() {
        let msg = body["error_description"]
            .as_str()
            .or_else(|| body["error"].as_str())
            .unwrap_or("unknown error");
        return Err(AppError::external_service(
            "bunyip-config",
            format!("token exchange failed ({status}): {msg}"),
        ));
    }
    body["access_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            AppError::external_service("bunyip-config", "token response missing access_token")
        })
}

async fn fetch_value(
    http: &reqwest::Client,
    config: &BunyipConfig,
    token: &str,
    key: &str,
) -> AppResult<Option<String>> {
    let url = format!("{}{CONFIG_PATH_PREFIX}{key}", config.base_url);
    let resp = http
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| AppError::external_service("bunyip-config", format!("config request: {e}")))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::external_service(
            "bunyip-config",
            format!("config read failed ({status}): {text}"),
        ));
    }
    // The endpoint's shape is `{ "value": "..." }` when it exists; a raw
    // string body is also accepted for robustness before Bunyip formalises
    // the response contract.
    let text = resp.text().await.unwrap_or_default();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(value) = json.get("value").and_then(|v| v.as_str()) {
            return Ok(Some(value.to_string()));
        }
        if let Some(value) = json.as_str() {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(Some(trimmed.to_string()))
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
