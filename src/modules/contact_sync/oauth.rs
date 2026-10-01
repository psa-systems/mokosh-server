//! PMS-1212 (PSA-70 phase 2): the Google OAuth client this integration needs.
//!
//! Deliberately not a general OAuth framework. PMS-837 removed the last one
//! (`crates/google-oauth-flow`) because it served a login path nothing called;
//! this is the authorization-code-with-PKCE flow for one provider, one scope
//! set, and one grant type, and it is the smallest thing that works.
//!
//! # Read-only is the permission, not the promise
//!
//! [`SCOPES`] is the whole of what this integration can ever do. `openid` and
//! `email` are identity scopes: they name the connected account for the
//! Settings card and grant nothing else. There is no write scope, so a bug
//! here cannot alter somebody's address book - which is the point of asking
//! for read-only rather than asking for everything and behaving.
//!
//! # What is a secret and where it lives
//!
//! The CLIENT secret is the TENANT's since PMS-1340: its own registration
//! first, then the deprecated deployment-wide client PMS-1264 stored on the
//! system tenant, then `GOOGLE_CONTACTS_CLIENT_SECRET` as a last resort, which
//! is what this module's doc used to describe as the only home. A tenant's
//! refresh token is the tenant's too and goes to the secret provider under
//! `SecretKind::ContactSync`. Neither is ever logged, and neither reaches an
//! error body: every failure below is reported by its shape, never by echoing
//! what was sent.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::app_secrets::{AppSecrets, GovernedSecret};
use crate::utils::error::{AppError, AppResult};

/// Google's authorization endpoint.
///
/// Fixed, and from operator configuration rather than tenant input, so it is
/// deliberately not screened by `utils::net::guard_outbound_url` - the same
/// exemption the Stripe API base has (PMS-805).
const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";

/// Everything this integration will ever be allowed to do.
///
/// `contacts.readonly` reads contacts. `openid` and `email` name the connected
/// account, which the Settings card shows so an admin can tell WHOSE address
/// book is feeding the CRM before they disconnect it (PSA-70 J and K).
/// Verified against Google's `people.get` reference: `contacts.readonly` alone
/// cannot read the authenticated account's own `emailAddresses`.
pub const SCOPES: &[&str] = &[CONTACTS_READONLY, "openid", "email"];

/// The one scope that actually reads an address book.
///
/// Named, because it is asked for in [`SCOPES`] and checked again in what came
/// BACK (see [`grants_contacts_read`]): Google's consent screen lets a person
/// untick an individual permission, so a successful exchange is not a granted
/// scope.
pub const CONTACTS_READONLY: &str = "https://www.googleapis.com/auth/contacts.readonly";

/// Whether a granted scope string covers reading contacts (PMS-1356).
///
/// The token response's `scope` is space-delimited and unordered, so it is
/// split rather than compared. The read-WRITE `.../auth/contacts` counts as
/// covering it, because it does: a person who granted more than was asked for
/// has not withheld the read, and what keeps this integration one-way is that
/// no code path writes (`google::tests::this_module_never_writes_to_google`),
/// not that the grant is narrow. Refusing a superset here would reject a
/// working connection over a permission nothing uses.
pub fn grants_contacts_read(granted: &str) -> bool {
    granted.split_whitespace().any(|scope| {
        scope == CONTACTS_READONLY || scope == "https://www.googleapis.com/auth/contacts"
    })
}

/// The deployment's OAuth client, absent when unconfigured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthClient {
    pub client_id: String,
    pub client_secret: String,
}

impl OauthClient {
    /// The HOST's client, read through the application-tier secret seam
    /// (PMS-1430).
    ///
    /// Which Google application this Mokosh installation authenticates as is a
    /// property of the deployment, not of a tenant, so it is one pair of
    /// governed secrets served by whichever `AppSecretProvider` the host
    /// declared. The seam is provider-agnostic: the hosted deployment declares
    /// the DATABASE provider (`SECRET_BACKEND` unset, so the `saas` hosting
    /// profile's default stands, PMS-1440), and a deployment may equally hold
    /// the pair in Infisical, a file or `{NAME}_FILE`.
    ///
    /// Three outcomes, and the third is the reason this returns a `Result`.
    /// Both halves present is a configured host. Neither is an unconfigured one,
    /// which the Settings card renders as "not available on this deployment"
    /// rather than as a Connect button that cannot work. One half without the
    /// other is neither: it is a host that would connect as half an application,
    /// so it is an error naming the key that is missing, raised at boot where an
    /// operator is present to read it rather than at a customer's first click.
    pub fn from_app_secrets(secrets: &AppSecrets) -> AppResult<Option<Self>> {
        let read = |secret: GovernedSecret| {
            secrets
                .get(secret)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        match (
            read(GovernedSecret::GoogleContactsClientId),
            read(GovernedSecret::GoogleContactsClientSecret),
        ) {
            (Some(client_id), Some(client_secret)) => Ok(Some(Self {
                client_id,
                client_secret,
            })),
            (None, None) => Ok(None),
            (Some(_), None) => Err(half_configured(GovernedSecret::GoogleContactsClientSecret)),
            (None, Some(_)) => Err(half_configured(GovernedSecret::GoogleContactsClientId)),
        }
    }
}

/// The client the running process is using, swappable while it runs
/// (PMS-1444).
///
/// `OauthClient::from_app_secrets` resolves once, in `main`, and the resolved
/// value is handed to the API service and to the worker service. That was fine
/// while the only way to set the pair was a shell on the box, because writing it
/// and restarting were the same action. PMS-1444 lets a deployment operator set
/// it from the product, and a setting whose effect waits for a deploy is a
/// setting that looks broken.
///
/// So the two services hold this instead of the value, and the write path swaps
/// it. This is `utils::email::SharedMailer` (PMS-638), deliberately: that is how
/// the deployment-wide SMTP settings already take effect without a restart, and
/// a second mechanism for the same problem would be a second thing to reason
/// about.
///
/// `None` is a configured state, not an uninitialised one: it is a deployment
/// with no Google client, which the Settings card renders as unavailable.
pub struct SharedGoogleClient {
    inner: std::sync::RwLock<Option<OauthClient>>,
}

impl SharedGoogleClient {
    pub fn new(inner: Option<OauthClient>) -> Self {
        Self {
            inner: std::sync::RwLock::new(inner),
        }
    }

    /// Replace the client. Takes effect on every consumer's next read, which
    /// for an OAuth flow means the next Connect or the next token refresh.
    pub fn swap(&self, inner: Option<OauthClient>) {
        *self
            .inner
            .write()
            .expect("SharedGoogleClient lock poisoned") = inner;
    }

    /// The client as of now. Cloned rather than borrowed so no caller holds the
    /// lock across an await: an OAuth exchange is a network round trip.
    pub fn current(&self) -> Option<OauthClient> {
        self.inner
            .read()
            .expect("SharedGoogleClient lock poisoned")
            .clone()
    }
}

impl std::fmt::Debug for SharedGoogleClient {
    /// Says whether a client is held, never which one. The struct holds a
    /// secret, so a derived `Debug` would put it in any error that formatted a
    /// service holding this.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedGoogleClient")
            .field("configured", &self.current().is_some())
            .finish()
    }
}

impl Default for SharedGoogleClient {
    /// An unconfigured deployment, for the test and seeder paths that never
    /// reach `main`.
    fn default() -> Self {
        Self::new(None)
    }
}

/// The boot error for a host holding one half of the pair.
///
/// Names the MISSING key rather than the present one, because the operator's
/// next action is to add it, and says where it goes without naming a provider:
/// which provider serves it is `SECRET_BACKEND`'s answer and the app-secret
/// survey already logs it one line above this.
fn half_configured(missing: GovernedSecret) -> AppError {
    AppError::Configuration(format!(
        "Google Contacts is half configured: {} is set and {} is not. A client id and its secret \
         have to come from the same Google project and the same provider, so add {} beside it or \
         remove both.",
        match missing {
            GovernedSecret::GoogleContactsClientSecret => GovernedSecret::GoogleContactsClientId,
            _ => GovernedSecret::GoogleContactsClientSecret,
        },
        missing,
        missing,
    ))
}

/// A PKCE verifier and the challenge derived from it.
///
/// The verifier stays server-side until the token exchange; only the challenge
/// travels with the browser. That is what makes an intercepted authorization
/// code useless on its own.
#[derive(Debug, Clone)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn generate() -> Self {
        // 64 characters from the crate's own CSPRNG helper, inside RFC 7636's
        // 43..128 range.
        let verifier = crate::utils::crypto::generate_token(64);
        Self::from_verifier(verifier)
    }

    /// S256, the only method Google accepts for a confidential client and the
    /// only one worth using: `plain` puts the verifier in the browser.
    pub fn from_verifier(verifier: String) -> Self {
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        Self {
            verifier,
            challenge,
        }
    }
}

/// The consent URL to send an admin to.
///
/// `access_type=offline` with `prompt=consent` is what produces a refresh
/// token: without the prompt Google returns one only on the first ever
/// consent, so a tenant that reconnects after a disconnect would get an access
/// token that expires in an hour and an integration that dies quietly
/// overnight.
pub fn authorization_url(
    client: &OauthClient,
    redirect_uri: &str,
    state: &str,
    pkce: &Pkce,
) -> String {
    let query = [
        ("client_id", client.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", &SCOPES.join(" ")),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("include_granted_scopes", "false"),
        ("state", state),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
    .collect::<Vec<_>>()
    .join("&");
    format!("{AUTH_ENDPOINT}?{query}")
}

/// What Google returned from the token endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// Absent on a refresh, and absent on an authorization exchange where the
    /// user had already consented and `prompt=consent` was not sent. The
    /// caller decides whether that is fatal; on a first connect it is.
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Why a token call failed, in terms the caller acts on.
///
/// `GrantRevoked` is its own shape because it is the one an admin can fix, and
/// it drives the `reconnect_required` connection state (PSA-70 J): Google
/// answers `invalid_grant` when the user removed the app's access, when the
/// refresh token was revoked, and when it simply expired, and all three mean
/// the same thing to a human - connect it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    GrantRevoked,
    Refused(String),
    Transport(String),
}

impl From<TokenError> for AppError {
    fn from(value: TokenError) -> Self {
        match value {
            TokenError::GrantRevoked => AppError::BadRequest(
                "Google has revoked this connection. Connect the account again.".to_string(),
            ),
            // The provider's own words, never the request: the request carried
            // the client secret and the authorization code.
            TokenError::Refused(detail) => {
                AppError::external_service("google", format!("token request refused: {detail}"))
            }
            TokenError::Transport(detail) => {
                AppError::external_service("google", format!("token request failed: {detail}"))
            }
        }
    }
}

/// Classify a token-endpoint error body. Pure, so the mapping is testable
/// without a network.
pub fn classify_token_error(status: u16, body: &str) -> TokenError {
    let error_code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_default();
    if error_code == "invalid_grant" {
        return TokenError::GrantRevoked;
    }
    let detail = if error_code.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("{error_code} (HTTP {status})")
    };
    TokenError::Refused(detail)
}

/// Exchange an authorization code for tokens.
pub async fn exchange_code(
    http: &reqwest::Client,
    client: &OauthClient,
    redirect_uri: &str,
    code: &str,
    pkce_verifier: &str,
) -> Result<TokenResponse, TokenError> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client.client_id.as_str()),
        ("client_secret", client.client_secret.as_str()),
        ("code_verifier", pkce_verifier),
    ];
    post_token(http, &form).await
}

/// Trade a refresh token for a fresh access token.
pub async fn refresh_access_token(
    http: &reqwest::Client,
    client: &OauthClient,
    refresh_token: &str,
) -> Result<TokenResponse, TokenError> {
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client.client_id.as_str()),
        ("client_secret", client.client_secret.as_str()),
    ];
    post_token(http, &form).await
}

async fn post_token(
    http: &reqwest::Client,
    form: &[(&str, &str)],
) -> Result<TokenResponse, TokenError> {
    let response = http
        .post(TOKEN_ENDPOINT)
        .form(form)
        .send()
        .await
        .map_err(|e| TokenError::Transport(e.to_string()))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(classify_token_error(status.as_u16(), &body));
    }
    serde_json::from_str(&body)
        .map_err(|e| TokenError::Refused(format!("token response was not understood: {e}")))
}

/// The connected account's email address, for the Settings card.
///
/// Read once at connect time and stored on the connection, rather than fetched
/// on every render: it is the answer to "whose address book is this", and it
/// has to keep being answerable after the grant is revoked, which is exactly
/// when the card most needs to name it.
pub async fn account_email(http: &reqwest::Client, access_token: &str) -> AppResult<String> {
    #[derive(Deserialize)]
    struct UserInfo {
        #[serde(default)]
        email: Option<String>,
    }
    let response = http
        .get(USERINFO_ENDPOINT)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| AppError::external_service("google", format!("userinfo failed: {e}")))?;
    if !response.status().is_success() {
        return Err(AppError::external_service(
            "google",
            format!("userinfo refused ({})", response.status()),
        ));
    }
    let info: UserInfo = response
        .json()
        .await
        .map_err(|e| AppError::external_service("google", format!("userinfo not JSON: {e}")))?;
    info.email
        .filter(|e| !e.trim().is_empty())
        .ok_or_else(|| AppError::external_service("google", "userinfo carried no email address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PMS-1356: what came back is checked, not assumed.
    ///
    /// Google's consent screen lets a person untick an individual permission and
    /// still finish the flow, so the exchange succeeds, a refresh token is
    /// stored, and the connection looks healthy until the first sync 403s. The
    /// read-write scope counts as covering the read because it does; what keeps
    /// this integration one-way is that nothing writes.
    #[test]
    fn a_granted_scope_without_contacts_does_not_read_contacts() {
        assert!(grants_contacts_read(
            "openid email https://www.googleapis.com/auth/contacts.readonly"
        ));
        assert!(
            grants_contacts_read("https://www.googleapis.com/auth/contacts"),
            "the read-write scope covers the read"
        );
        assert!(
            !grants_contacts_read("openid email"),
            "the contacts permission was unticked on the consent screen"
        );
        assert!(!grants_contacts_read(""));
        assert!(
            !grants_contacts_read("https://www.googleapis.com/auth/contacts.other.readonly"),
            "a scope that merely starts the same way is a different scope"
        );
    }

    /// The scope set is the whole permission surface, so it is pinned rather
    /// than trusted: a write scope added here is a bug that reaches somebody's
    /// address book.
    #[test]
    fn the_scopes_are_read_only() {
        assert_eq!(
            SCOPES,
            &[
                "https://www.googleapis.com/auth/contacts.readonly",
                "openid",
                "email"
            ]
        );
        for scope in SCOPES {
            assert!(
                !scope.ends_with("/contacts"),
                "{scope} is the read-write contacts scope"
            );
            for writable in ["directory", "other.contacts", "userinfo.profile"] {
                assert!(!scope.contains(writable), "{scope} widens beyond read-only");
            }
        }
    }

    /// The consent URL carries what makes the flow safe, and carries no
    /// secret: the client SECRET is only ever sent server-to-server.
    #[test]
    fn the_consent_url_is_pkce_and_offline_and_holds_no_secret() {
        let client = OauthClient {
            client_id: "client-id".to_string(),
            client_secret: "super-secret".to_string(),
        };
        let pkce = Pkce::from_verifier("verifier-value".to_string());
        let url = authorization_url(
            &client,
            "https://api.example.com/api/v1/public/contact-sync/google/callback",
            "state-token",
            &pkce,
        );
        assert!(url.starts_with(AUTH_ENDPOINT), "{url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(
            url.contains(&format!("code_challenge={}", pkce.challenge)),
            "{url}"
        );
        assert!(url.contains("access_type=offline"), "{url}");
        assert!(url.contains("prompt=consent"), "{url}");
        assert!(url.contains("state=state-token"), "{url}");
        assert!(
            !url.contains("super-secret"),
            "the client secret must never reach the browser: {url}"
        );
        assert!(
            !url.contains("verifier-value"),
            "the PKCE verifier must never reach the browser: {url}"
        );
    }

    /// S256 is the digest of the verifier, base64url without padding. Pinned
    /// against a hand-computed vector so a change of encoding fails here
    /// rather than at Google.
    #[test]
    fn the_challenge_is_the_s256_of_the_verifier() {
        let pkce = Pkce::from_verifier("abc123".to_string());
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(b"abc123"));
        assert_eq!(pkce.challenge, expected);
        assert!(!pkce.challenge.contains('='), "no padding");
        assert!(
            !pkce.challenge.contains('+') && !pkce.challenge.contains('/'),
            "url-safe"
        );
    }

    /// A generated verifier is inside RFC 7636's length range and is not the
    /// challenge.
    #[test]
    fn a_generated_verifier_is_long_enough_and_is_not_the_challenge() {
        let pkce = Pkce::generate();
        assert!(
            (43..=128).contains(&pkce.verifier.len()),
            "{}",
            pkce.verifier.len()
        );
        assert_ne!(pkce.verifier, pkce.challenge);
    }

    /// `invalid_grant` is the one an admin can fix, so it gets its own shape
    /// and drives `reconnect_required` rather than reading as a failed sync.
    #[test]
    fn a_revoked_grant_is_told_apart_from_every_other_refusal() {
        assert_eq!(
            classify_token_error(400, r#"{"error":"invalid_grant"}"#),
            TokenError::GrantRevoked
        );
        assert_eq!(
            classify_token_error(401, r#"{"error":"invalid_client"}"#),
            TokenError::Refused("invalid_client (HTTP 401)".to_string())
        );
        assert_eq!(
            classify_token_error(500, "not json at all"),
            TokenError::Refused("HTTP 500".to_string())
        );
    }

    /// No failure carries what was sent. The request held the client secret,
    /// the authorization code and the refresh token; an error body that echoed
    /// any of them would put all three in a log and a client response.
    #[test]
    fn no_error_message_carries_the_request() {
        let messages = [
            AppError::from(TokenError::GrantRevoked).to_string(),
            AppError::from(TokenError::Refused("invalid_client (HTTP 401)".into())).to_string(),
            AppError::from(TokenError::Transport("connection reset".into())).to_string(),
        ];
        for message in messages {
            for secret in [
                "super-secret",
                "auth-code",
                "refresh-token",
                "code_verifier",
            ] {
                assert!(!message.contains(secret), "{message}");
            }
        }
    }
}

#[cfg(test)]
mod pms1430_host_client {
    use super::*;
    use crate::app_secrets::{AppSecretProvider, AppSecretProviderKind};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A provider holding whatever the case puts in it, so the four shapes of
    /// the pair can be driven without standing up a real provider.
    struct Fixed(HashMap<&'static str, String>);

    #[async_trait]
    impl AppSecretProvider for Fixed {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn get(&self, secret: GovernedSecret) -> Option<String> {
            self.0.get(secret.name()).cloned()
        }
    }

    fn secrets(pairs: &[(GovernedSecret, &str)]) -> AppSecrets {
        let map = pairs
            .iter()
            .map(|(secret, value)| (secret.name(), (*value).to_string()))
            .collect();
        AppSecrets::with_provider(AppSecretProviderKind::Infisical, Arc::new(Fixed(map)))
    }

    const ID: GovernedSecret = GovernedSecret::GoogleContactsClientId;
    const SECRET: GovernedSecret = GovernedSecret::GoogleContactsClientSecret;

    /// Both halves present is a configured host.
    #[test]
    fn a_complete_pair_is_the_host_client() {
        let client = OauthClient::from_app_secrets(&secrets(&[
            (ID, "host.apps.googleusercontent.com"),
            (SECRET, "s3cret"),
        ]))
        .expect("a complete pair resolves")
        .expect("and is Some");
        assert_eq!(client.client_id, "host.apps.googleusercontent.com");
        assert_eq!(client.client_secret, "s3cret");
    }

    /// Neither half is a deployment that cannot connect, which is a state, not
    /// an error: most self-hosted deployments never turn Google Contacts on.
    #[test]
    fn neither_half_is_an_unconfigured_host() {
        assert!(OauthClient::from_app_secrets(&secrets(&[]))
            .expect("unconfigured is not an error")
            .is_none());
    }

    /// Whitespace is not configuration. A provider that hands back an empty
    /// string (a forwarded-but-unset compose key arrives as `""`) reads as
    /// absent rather than as half a pair.
    #[test]
    fn a_blank_value_reads_as_absent() {
        assert!(
            OauthClient::from_app_secrets(&secrets(&[(ID, "   "), (SECRET, "")]))
                .expect("blank is unconfigured")
                .is_none()
        );
    }

    /// One half without the other is neither state, and it is the one worth
    /// failing on: a host that would connect as half an application.
    #[test]
    fn half_a_pair_names_the_missing_key() {
        let err =
            OauthClient::from_app_secrets(&secrets(&[(ID, "host.apps.googleusercontent.com")]))
                .expect_err("an id with no secret is an error");
        let message = err.to_string();
        assert!(message.contains(SECRET.name()), "{message}");
        assert!(
            !message.contains("host.apps.googleusercontent.com"),
            "the error names keys, never values: {message}"
        );

        let err = OauthClient::from_app_secrets(&secrets(&[(SECRET, "s3cret")]))
            .expect_err("a secret with no id is an error");
        let message = err.to_string();
        assert!(message.contains(ID.name()), "{message}");
        assert!(
            !message.contains("s3cret"),
            "the error must never carry the secret: {message}"
        );
    }
}
