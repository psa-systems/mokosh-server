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
//! The CLIENT secret is operator configuration (`GOOGLE_CONTACTS_CLIENT_SECRET`),
//! beside `INFISICAL_CLIENT_SECRET`, because it belongs to the deployment. A
//! TENANT's refresh token is the tenant's and goes to the secret provider
//! under `SecretKind::ContactSync`. Neither is ever logged, and neither
//! reaches an error body: every failure below is reported by its shape, never
//! by echoing what was sent.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

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
pub const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/contacts.readonly",
    "openid",
    "email",
];

/// The deployment's OAuth client, absent when unconfigured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthClient {
    pub client_id: String,
    pub client_secret: String,
}

impl OauthClient {
    /// Read from operator configuration. `None` when either key is unset,
    /// which the Settings card renders as "not configured" rather than as a
    /// Connect button that cannot work.
    pub fn from_config() -> Option<Self> {
        let client_id = crate::config::get(&crate::config::registry::GOOGLE_CONTACTS_CLIENT_ID)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())?;
        let client_secret =
            crate::config::get(&crate::config::registry::GOOGLE_CONTACTS_CLIENT_SECRET)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())?;
        Some(Self {
            client_id,
            client_secret,
        })
    }
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
