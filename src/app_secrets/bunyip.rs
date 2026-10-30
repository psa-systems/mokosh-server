//! The Bunyip provider: reads a host secret bunyip holds on the suite's
//! behalf (PMS-1537).
//!
//! bunyip is the suite's identity provider and already holds the facts every
//! product shares. One of them is the Google OAuth client a hosted Mokosh uses
//! to sync a customer's contacts: PMS-1430 made it an application-tier secret,
//! and until now an operator set it in bunyip for bunyip's own use and then
//! pasted the same pair into Mokosh's declared provider. Two homes for one
//! value, and two chances to rotate only one of them.
//!
//! BUNYIP-983 put that pair behind `GET /v1/host/secrets/{KEY}`, so this
//! provider reads it from there and the paste goes away.
//!
//! ## One key, two governed secrets
//!
//! bunyip serves `mokosh/google_oauth_client` as ONE key whose value is the
//! JSON pair `{"client_id": "...", "client_secret": "..."}`, because a reader
//! wants both halves or neither: an id from one Google project with the secret
//! from another fails at Google with an error nobody can place. This provider
//! fetches that key once at [`BunyipProvider::load`] and serves both
//! [`GovernedSecret::GoogleContactsClientId`] and
//! [`GovernedSecret::GoogleContactsClientSecret`] from the one response, which
//! is also what keeps the pair's halves from being declared to different
//! providers by accident.
//!
//! ## Authentication is HTTP Basic
//!
//! Not a bearer, and not because Basic is nicer: bunyip's `/oauth2/token`
//! implements `authorization_code` and `refresh_token` only, so there is no
//! machine bearer to obtain. `client_credentials` is a registration marker its
//! machine endpoints check while authenticating the Basic credential directly,
//! which is how the mailer relay has worked since BUNYIP-602. The credential is
//! its own registration with its own one-key allow-list, so a leak of it
//! exposes this pair and nothing else (BUNYIP-855 D9).
//!
//! ## Read-only, on purpose
//!
//! bunyip owns the value. `is_writable` is false and the trait's refusing
//! defaults for `set` and `delete` stand, so `provider-set` and
//! `provider-purge` name this provider as unwritable instead of writing a copy
//! Mokosh would then serve while bunyip holds a different one.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use serde::Deserialize;

use super::{AppSecretProvider, GovernedSecret};
use crate::utils::error::{AppError, AppResult};

/// The one key this provider reads, as bunyip spells it.
const HOST_SECRET_KEY: &str = "mokosh/google_oauth_client";

/// Bunyip's own per-request budget, sized like the configuration provider's
/// (`src/config/bunyip.rs`): one call at boot, and a boot that hangs on an
/// unreachable host is worse than one that fails.
const TIMEOUT: Duration = Duration::from_secs(10);

/// What bunyip needs to be reached: the base URL and the machine credential.
///
/// Read from the environment rather than through [`crate::config::get`] for
/// the reason every provider's construction inputs are: enablement is
/// bootstrap configuration, and configuration that locates configuration
/// cannot live inside what it locates (`docs/providers.md`).
#[derive(Debug, Clone)]
pub struct BunyipSecretsConfig {
    pub base_url: String,
    pub client_id: String,
    pub client_secret: String,
}

impl BunyipSecretsConfig {
    /// `None` when the deployment has not named a bunyip to read from, which
    /// is every self-hosted deployment.
    pub fn from_env() -> AppResult<Option<Self>> {
        Self::resolve(
            &read_var(BUNYIP_SECRETS_URL_VAR),
            &read_secret_var(BUNYIP_SECRETS_CLIENT_ID_VAR),
            &read_secret_var(BUNYIP_SECRETS_CLIENT_SECRET_VAR),
        )
    }

    /// The rule itself, split out so it can be tested without writing to
    /// process-global env under a concurrent test runner, exactly as
    /// [`crate::app_secrets::AppSecretsSelection::resolve`] is.
    ///
    /// A URL with half a credential is an error rather than `None`: the
    /// operator plainly meant to configure this, and a silent `None` would
    /// make the secret look merely absent.
    pub fn resolve(
        base_url: &str,
        client_id: &str,
        client_secret: &str,
    ) -> AppResult<Option<Self>> {
        let base_url = base_url.trim();
        if base_url.is_empty() {
            return Ok(None);
        }
        let (client_id, client_secret) = (client_id.trim(), client_secret.trim());
        if client_id.is_empty() || client_secret.is_empty() {
            return Err(AppError::Configuration(format!(
                "{BUNYIP_SECRETS_URL_VAR} is set, so {BUNYIP_SECRETS_CLIENT_ID_VAR} and \
                 {BUNYIP_SECRETS_CLIENT_SECRET_VAR} are both required: bunyip authenticates \
                 the read with an HTTP Basic machine credential. Register one in bunyip with \
                 `bunyip-api machine-client register --name mokosh-host-secrets --secret-key \
                 {HOST_SECRET_KEY}`."
            )));
        }
        Ok(Some(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
        }))
    }
}

/// `BUNYIP_SECRETS_URL`: where bunyip serves the host-secrets route.
pub const BUNYIP_SECRETS_URL_VAR: &str = "BUNYIP_SECRETS_URL";
/// `BUNYIP_SECRETS_CLIENT_ID`: the machine registration's client id.
pub const BUNYIP_SECRETS_CLIENT_ID_VAR: &str = "BUNYIP_SECRETS_CLIENT_ID";
/// `BUNYIP_SECRETS_CLIENT_SECRET`: that registration's secret.
pub const BUNYIP_SECRETS_CLIENT_SECRET_VAR: &str = "BUNYIP_SECRETS_CLIENT_SECRET";

fn read_var(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_string()
}

/// A credential, read file-first: `{NAME}_FILE` is the compose-secret form the
/// environment provider already insists on (PMS-988), because a plain
/// `NAME=value` in a compose `environment:` block is visible to
/// `docker inspect` and to every child process.
fn read_secret_var(name: &str) -> String {
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
                    "{name}_FILE points at an unreadable file, so the bunyip app-secret \
                     provider has no credential from it"
                );
                None
            }
        })
        .filter(|value| !value.is_empty());
    from_file.unwrap_or_else(|| read_var(name))
}

/// bunyip's envelope. `data.value` is a STRING holding the JSON pair, not the
/// pair itself, so it is parsed in two steps.
#[derive(Debug, Deserialize)]
struct HostSecretEnvelope {
    data: HostSecretData,
}

#[derive(Debug, Deserialize)]
struct HostSecretData {
    value: String,
}

/// The pair, as bunyip's `mokosh/google_oauth_client` carries it.
#[derive(Debug, Deserialize)]
struct GoogleOauthClient {
    client_id: String,
    client_secret: String,
}

/// The bunyip-backed application-tier secret provider.
pub struct BunyipProvider {
    values: HashMap<&'static str, String>,
}

/// Hand-written rather than derived: a derive would print the cached values,
/// and a provider that renders its secrets into a panic message or a debug log
/// is the leak this tier exists to prevent. The count is the useful fact.
impl std::fmt::Debug for BunyipProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BunyipProvider")
            .field("secrets_held", &self.values.len())
            .finish()
    }
}

impl BunyipProvider {
    /// Fetch the host secret once and cache both halves.
    ///
    /// Every failure is an error and none is silently `None`, because this
    /// provider is only built when the deployment named a bunyip to read from.
    /// Each one names its own remedy, since they are fixed in three different
    /// places: a 403 is bunyip's allow-list, a 404 is bunyip's admin page, and
    /// a transport failure is the URL or the network between them.
    pub async fn load(config: &BunyipSecretsConfig) -> AppResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| {
                AppError::Configuration(format!("could not build the bunyip HTTP client: {e}"))
            })?;
        let url = format!("{}/v1/host/secrets/{HOST_SECRET_KEY}", config.base_url);
        let credential = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", config.client_id, config.client_secret));

        let response = http
            .get(&url)
            .header("Authorization", format!("Basic {credential}"))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                AppError::Configuration(format!(
                    "could not reach bunyip at {url} to read {HOST_SECRET_KEY}: {e}. Check \
                     {BUNYIP_SECRETS_URL_VAR} and that bunyip is reachable from this host."
                ))
            })?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(AppError::Configuration(format!(
                "bunyip refused this deployment's host-secrets credential (401). The \
                 registration named by {BUNYIP_SECRETS_CLIENT_ID_VAR} is unknown, disabled or \
                 holds a different secret; rotate it with `bunyip-api machine-client rotate \
                 --client-id <id>` and update {BUNYIP_SECRETS_CLIENT_SECRET_VAR}."
            )));
        }
        if status == reqwest::StatusCode::FORBIDDEN {
            return Err(AppError::Configuration(format!(
                "bunyip holds {HOST_SECRET_KEY} but this registration may not read it (403). \
                 Add the key to its allow-list: `bunyip-api machine-client register --name \
                 mokosh-host-secrets --secret-key {HOST_SECRET_KEY}`, or add it to the \
                 existing registration's allowed_secret_keys."
            )));
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(AppError::Configuration(format!(
                "bunyip serves no value for {HOST_SECRET_KEY} (404). An administrator sets the \
                 Google OAuth client under Admin > Mokosh in bunyip; until then no Mokosh \
                 tenant on this deployment can connect their Google account."
            )));
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Configuration(format!(
                "bunyip answered {status} for {HOST_SECRET_KEY}: {body}"
            )));
        }

        let envelope: HostSecretEnvelope = response.json().await.map_err(|e| {
            AppError::Configuration(format!(
                "bunyip's answer for {HOST_SECRET_KEY} was not the expected envelope: {e}"
            ))
        })?;
        let pair: GoogleOauthClient = serde_json::from_str(&envelope.data.value).map_err(|e| {
            AppError::Configuration(format!(
                "bunyip's {HOST_SECRET_KEY} value is not a client_id / client_secret pair: {e}"
            ))
        })?;

        Ok(Self::from_pair(&pair.client_id, &pair.client_secret))
    }

    /// The cache, built from a pair. Split from the fetch so the unit tests
    /// exercise the mapping without a bunyip.
    fn from_pair(client_id: &str, client_secret: &str) -> Self {
        let mut values: HashMap<&'static str, String> = HashMap::new();
        for (secret, value) in [
            (GovernedSecret::GoogleContactsClientId, client_id),
            (GovernedSecret::GoogleContactsClientSecret, client_secret),
        ] {
            let value = value.trim();
            if !value.is_empty() {
                values.insert(secret.name(), value.to_string());
            }
        }
        Self { values }
    }
}

#[async_trait]
impl AppSecretProvider for BunyipProvider {
    fn name(&self) -> &'static str {
        "bunyip"
    }

    fn get(&self, secret: GovernedSecret) -> Option<String> {
        self.values.get(secret.name()).cloned()
    }

    fn has(&self, secret: GovernedSecret) -> bool {
        self.values.contains_key(secret.name())
    }

    /// bunyip owns the value, so this provider never takes a write. The
    /// trait's `set` and `delete` defaults refuse by name, which is what
    /// `provider-set` reports instead of writing a copy that would then
    /// disagree with bunyip.
    fn is_writable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_one_key_feeds_both_halves_of_the_pair() {
        let provider = BunyipProvider::from_pair(
            "123456789012-abc.apps.googleusercontent.com",
            "fixture-client-secret",
        );
        assert_eq!(
            provider
                .get(GovernedSecret::GoogleContactsClientId)
                .as_deref(),
            Some("123456789012-abc.apps.googleusercontent.com")
        );
        assert_eq!(
            provider
                .get(GovernedSecret::GoogleContactsClientSecret)
                .as_deref(),
            Some("fixture-client-secret")
        );
    }

    /// Every other governed secret is somebody else's: bunyip serves one key,
    /// and a provider that answered for the SMTP password would make the
    /// classification think the declared provider held it.
    #[test]
    fn it_answers_for_nothing_else() {
        let provider = BunyipProvider::from_pair("id", "secret");
        for secret in GovernedSecret::ALL {
            if matches!(
                secret,
                GovernedSecret::GoogleContactsClientId | GovernedSecret::GoogleContactsClientSecret
            ) {
                continue;
            }
            assert!(
                !provider.has(secret),
                "{} is not bunyip's to serve",
                secret.name()
            );
        }
    }

    /// A blank half is not a value, the `non_empty` rule every provider here
    /// follows: half a pair would otherwise read as held and fail at Google.
    #[test]
    fn a_blank_half_is_not_held() {
        let provider = BunyipProvider::from_pair("  ", "fixture-client-secret");
        assert!(!provider.has(GovernedSecret::GoogleContactsClientId));
        assert!(provider.has(GovernedSecret::GoogleContactsClientSecret));
    }

    #[test]
    fn it_is_not_writable() {
        assert!(!BunyipProvider::from_pair("id", "secret").is_writable());
    }

    /// A URL with half a credential is a configuration error, not "no bunyip
    /// configured": the operator meant to read from bunyip and a silent
    /// `None` would make the secret look merely absent.
    #[test]
    fn a_url_without_a_credential_is_refused_by_name() {
        let error = BunyipSecretsConfig::resolve("https://bunyip.test", "", "")
            .expect_err("half a credential is refused");
        let message = error.to_string();
        assert!(message.contains(BUNYIP_SECRETS_CLIENT_ID_VAR), "{message}");
        assert!(
            message.contains("machine-client register"),
            "and names how to make one: {message}"
        );
    }

    #[test]
    fn no_url_means_no_bunyip_provider() {
        assert!(
            BunyipSecretsConfig::resolve("   ", "id", "secret")
                .expect("blank is not an error")
                .is_none(),
            "every self-hosted deployment reads this way"
        );
    }
}
