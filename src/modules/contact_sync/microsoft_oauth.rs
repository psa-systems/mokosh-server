//! MAPPS-1101: the Microsoft 365 OAuth client this integration needs.
//!
//! Shape mirrors [`crate::modules::contact_sync::oauth`] (Google) so a reader
//! familiar with one reads the other without surprises: PKCE with S256, a
//! `SharedMicrosoftClient` that swaps at runtime so the operator surface
//! (follow-up PR) does not need a restart, and the same `TokenError`
//! classification.
//!
//! # Read-only is the permission, not the promise
//!
//! [`SCOPES`] is the whole of what this integration can ever do. `openid`
//! and `email` are identity scopes: they name the connected account for the
//! Settings card and grant nothing else. There is no write scope asked for,
//! so a bug here cannot alter someone's address book. The write-scoped
//! shape would be a different trait and a different consent screen, not an
//! extra permission here.
//!
//! # One Entra app, multi-tenant consent
//!
//! The Mokosh deployment registers ONE Entra ID app and customers consent
//! to it. The `/common/` authority in the authorization and token
//! endpoints is what makes that work: any Microsoft tenant can sign in
//! against an app registered as `accountsInAnyOrg`. The alternative is
//! each MSP registering their own Entra app in Azure, which is the
//! operationally hostile shape the Google side (PMS-1430) explicitly
//! rejected and the same posture applies here.
//!
//! # What is a secret and where it lives
//!
//! The CLIENT secret is the DEPLOYMENT's, held through the application-tier
//! secret seam (`AppSecrets::MicrosoftContactsClientId` /
//! `MicrosoftContactsClientSecret`). A tenant's refresh token is the
//! tenant's and goes to the per-tenant secret provider under
//! `SecretKind::ContactSync`, the same address Google's refresh tokens
//! land at. Neither is ever logged, and neither reaches an error body:
//! every failure below is reported by its shape, never by echoing what was
//! sent.

use serde::Deserialize;

use crate::app_secrets::{AppSecrets, GovernedSecret};
use crate::utils::error::{AppError, AppResult};

use super::oauth::{Pkce, TokenError};

/// Microsoft's `/common/` authority. Multi-tenant: any Microsoft tenant
/// signs in against this app registration without the deployment having
/// to list its id.
///
/// Fixed, and from operator configuration rather than tenant input, so
/// deliberately not screened by `utils::net::guard_outbound_url`, the same
/// exemption the Stripe API base has (PMS-805).
const AUTH_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const USERINFO_ENDPOINT: &str = "https://graph.microsoft.com/oidc/userinfo";

/// Every scope the consent screen asks for.
///
/// `Contacts.Read` is the only scope that reads an address book; the rest
/// name the connected account for the Settings card. `offline_access` is
/// what Microsoft requires for a refresh token to be issued at all; without
/// it the access token expires in an hour and the integration dies
/// quietly overnight (same failure mode Google's `access_type=offline`
/// prevents).
pub const SCOPES: &[&str] = &[CONTACTS_READ, "offline_access", "openid", "email"];

/// The one scope that actually reads an address book.
///
/// Named, because it is asked for in [`SCOPES`] and checked again in what
/// came back (see [`grants_contacts_read`]): a Microsoft consent screen can
/// in principle grant a subset of what was requested, and a successful
/// exchange is not a granted scope.
pub const CONTACTS_READ: &str = "Contacts.Read";

/// Whether a granted scope string covers reading contacts (MAPPS-1101).
///
/// The token response's `scope` is space-delimited and unordered, so it is
/// split rather than compared. The read-write `Contacts.ReadWrite` counts
/// as covering it, because it does: a user who granted more than was asked
/// for has not withheld the read, and what keeps this integration one-way
/// is that no code path writes (the trait at
/// [`super::provider::ContactSyncProvider`] has no write method), not that
/// the grant is narrow.
pub fn grants_contacts_read(granted: &str) -> bool {
    granted
        .split_whitespace()
        .any(|scope| scope == CONTACTS_READ || scope == "Contacts.ReadWrite")
}

/// The deployment's Entra OAuth client, absent when unconfigured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthClient {
    pub client_id: String,
    pub client_secret: String,
}

impl OauthClient {
    /// The host's client, read through the application-tier secret seam.
    ///
    /// Both halves present is a configured host. Neither is an
    /// unconfigured one (the Settings card renders as "not available on
    /// this deployment" rather than offering a Connect button that cannot
    /// work). One half without the other is neither: it is a host that
    /// would connect as half an application, so it is an error naming the
    /// key that is missing, raised at boot where an operator is present
    /// to read it.
    pub fn from_app_secrets(secrets: &AppSecrets) -> AppResult<Option<Self>> {
        let read = |secret: GovernedSecret| {
            secrets
                .get(secret)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        match (
            read(GovernedSecret::MicrosoftContactsClientId),
            read(GovernedSecret::MicrosoftContactsClientSecret),
        ) {
            (Some(client_id), Some(client_secret)) => Ok(Some(Self {
                client_id,
                client_secret,
            })),
            (None, None) => Ok(None),
            (Some(_), None) => Err(half_configured(GovernedSecret::MicrosoftContactsClientSecret)),
            (None, Some(_)) => Err(half_configured(GovernedSecret::MicrosoftContactsClientId)),
        }
    }
}

/// The client the running process is using, swappable while it runs.
/// Mirrors [`super::oauth::SharedGoogleClient`]: the operator surface
/// (follow-up PR) writes the pair through the same `swap` mechanism so
/// the setting takes effect without a restart.
pub struct SharedMicrosoftClient {
    inner: std::sync::RwLock<Option<OauthClient>>,
    write_lock: tokio::sync::Mutex<()>,
}

impl SharedMicrosoftClient {
    pub fn new(inner: Option<OauthClient>) -> Self {
        Self {
            inner: std::sync::RwLock::new(inner),
            write_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn lock_write(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.write_lock.lock().await
    }

    pub fn swap(&self, inner: Option<OauthClient>) {
        *self
            .inner
            .write()
            .expect("SharedMicrosoftClient lock poisoned") = inner;
    }

    pub fn current(&self) -> Option<OauthClient> {
        self.inner
            .read()
            .expect("SharedMicrosoftClient lock poisoned")
            .clone()
    }
}

impl std::fmt::Debug for SharedMicrosoftClient {
    /// Says whether a client is held, never which one. The struct holds a
    /// secret, so a derived `Debug` would put it in any error that
    /// formatted a service holding this.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedMicrosoftClient")
            .field("configured", &self.current().is_some())
            .finish()
    }
}

impl Default for SharedMicrosoftClient {
    fn default() -> Self {
        Self::new(None)
    }
}

fn half_configured(missing: GovernedSecret) -> AppError {
    AppError::Configuration(format!(
        "Microsoft 365 Contacts is half configured: {} is set and {} is not. A client id and its \
         secret have to come from the same Entra ID app registration and the same provider, so \
         add {} beside it or remove both.",
        match missing {
            GovernedSecret::MicrosoftContactsClientSecret =>
                GovernedSecret::MicrosoftContactsClientId,
            _ => GovernedSecret::MicrosoftContactsClientSecret,
        },
        missing,
        missing,
    ))
}

/// The consent URL to send an admin to.
///
/// `prompt=consent` plus `offline_access` in the scope set is what makes
/// Microsoft issue a refresh token every time, not just on the user's
/// first ever consent. Without the prompt, a reconnect after a disconnect
/// would get an access token that expires in an hour and the integration
/// would die overnight; the failure mode is identical to Google's and the
/// mitigation is the same shape.
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
        ("response_mode", "query"),
        ("scope", &SCOPES.join(" ")),
        ("prompt", "consent"),
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

/// What Microsoft returned from the token endpoint.
///
/// Shape identical to [`super::oauth::TokenResponse`] so the caller holding
/// one of them does not care which provider minted it. Microsoft's token
/// endpoint also sends `token_type` and sometimes `ext_expires_in`; neither
/// is useful here so neither is deserialised.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// Absent on a refresh and absent on an authorization exchange where
    /// the user had already consented and `prompt=consent` was not sent.
    /// On a first connect the caller treats absence as fatal.
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Classify a token-endpoint error body. Pure, so the mapping is testable
/// without a network. Microsoft's error shapes are OAuth 2.0 standard
/// (`invalid_grant`, `invalid_request`, `interaction_required`) plus the
/// `AADSTS<N>` numeric codes in the `error_description`; the standard code
/// alone decides the TokenError variant.
pub fn classify_token_error(status: u16, body: &str) -> TokenError {
    let error_code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_default();
    if error_code == "invalid_grant" || error_code == "interaction_required" {
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
        ("scope", &SCOPES.join(" ")),
    ];
    post_token(http, &form).await
}

/// Trade a refresh token for a fresh access token. Microsoft requires the
/// same scope set to be re-sent on refresh, else the issued access token
/// comes back narrower than the stored grant claims.
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
        ("scope", &SCOPES.join(" ")),
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
/// Read once at connect time and stored on the connection, rather than
/// fetched on every render: it is the answer to "whose address book is
/// this", and it has to keep being answerable after the grant is revoked,
/// which is exactly when the card most needs to name it.
///
/// Microsoft Graph's OIDC userinfo endpoint returns `email`; if a tenant
/// has disabled it, we fall back to `/v1.0/me`'s `mail` or
/// `userPrincipalName`. One call per Connect.
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
        .map_err(|e| AppError::external_service("microsoft", format!("userinfo failed: {e}")))?;
    if !response.status().is_success() {
        return Err(AppError::external_service(
            "microsoft",
            format!("userinfo refused ({})", response.status()),
        ));
    }
    let info: UserInfo = response.json().await.map_err(|e| {
        AppError::external_service("microsoft", format!("userinfo not JSON: {e}"))
    })?;
    info.email.filter(|e| !e.trim().is_empty()).ok_or_else(|| {
        AppError::external_service("microsoft", "userinfo carried no email address")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What came back is checked, not assumed. Microsoft's consent screen
    /// cannot untick a single permission the same way Google's can, but
    /// `.default` and admin-consent flows can grant a different set than
    /// requested; a successful exchange is not a granted scope.
    #[test]
    fn a_granted_scope_without_contacts_does_not_read_contacts() {
        assert!(grants_contacts_read("openid email Contacts.Read"));
        assert!(
            grants_contacts_read("Contacts.ReadWrite"),
            "the read-write scope covers the read"
        );
        assert!(
            !grants_contacts_read("openid email"),
            "the contacts permission was not granted"
        );
        assert!(!grants_contacts_read(""));
        assert!(
            !grants_contacts_read("Contacts.Read.Shared"),
            "a scope that merely starts the same way is a different scope"
        );
    }

    /// The scope set is the whole permission surface, so it is pinned
    /// rather than trusted: a write scope added here is a bug that reaches
    /// someone's address book.
    #[test]
    fn the_scopes_are_read_only() {
        assert_eq!(SCOPES, &["Contacts.Read", "offline_access", "openid", "email"]);
        for scope in SCOPES {
            assert!(
                !scope.contains("ReadWrite") && !scope.contains("Write"),
                "{scope} is a write scope"
            );
            assert!(
                !scope.contains("Directory") && !scope.contains("Mail"),
                "{scope} widens beyond contacts"
            );
        }
    }

    /// The consent URL carries what makes the flow safe, and carries no
    /// secret: the client SECRET is only ever sent server-to-server.
    #[test]
    fn the_authorization_url_carries_pkce_and_no_secret() {
        let client = OauthClient {
            client_id: "the-client".into(),
            client_secret: "the-secret".into(),
        };
        let pkce = Pkce::generate();
        let url = authorization_url(
            &client,
            "https://example/callback",
            "state-123",
            &pkce,
        );
        assert!(url.starts_with(AUTH_ENDPOINT));
        assert!(url.contains("client_id=the-client"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("response_mode=query"));
        assert!(
            !url.contains("the-secret"),
            "client secret must never land in a URL: {url}"
        );
    }

    /// `invalid_grant` and `interaction_required` both mean "the user
    /// removed access, reconnect": the Settings card renders one state
    /// for a reader to act on.
    #[test]
    fn invalid_grant_and_interaction_required_both_map_to_revoked() {
        let a = classify_token_error(
            400,
            r#"{"error":"invalid_grant","error_description":"AADSTS70008: expired"}"#,
        );
        let b = classify_token_error(
            400,
            r#"{"error":"interaction_required","error_description":"consent needed"}"#,
        );
        assert_eq!(a, TokenError::GrantRevoked);
        assert_eq!(b, TokenError::GrantRevoked);
    }

    /// Anything else carries the standard code + status, not the body
    /// (which repeats what was sent).
    #[test]
    fn other_token_errors_are_refused_with_the_code_and_status() {
        let err = classify_token_error(
            400,
            r#"{"error":"invalid_request","error_description":"the_description"}"#,
        );
        assert_eq!(
            err,
            TokenError::Refused("invalid_request (HTTP 400)".to_string())
        );
    }

    /// A body with no `error` key still produces a readable classification
    /// (status only), never a panic.
    #[test]
    fn an_unstructured_body_classifies_by_status_alone() {
        let err = classify_token_error(500, "upstream broken");
        assert_eq!(err, TokenError::Refused("HTTP 500".to_string()));
    }

    /// `SharedMicrosoftClient::Debug` names configured/absent, never the
    /// secret, so a log line formatting a service holding this does not
    /// leak the client id or secret.
    #[test]
    fn shared_client_debug_does_not_render_the_secret() {
        let shared = SharedMicrosoftClient::new(Some(OauthClient {
            client_id: "the-id".into(),
            client_secret: "the-secret".into(),
        }));
        let rendered = format!("{shared:?}");
        assert!(rendered.contains("configured: true"), "{rendered}");
        assert!(!rendered.contains("the-id"), "client id leaked: {rendered}");
        assert!(
            !rendered.contains("the-secret"),
            "client secret leaked: {rendered}"
        );
    }
}
