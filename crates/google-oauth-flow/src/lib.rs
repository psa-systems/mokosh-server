//! Reusable Google OAuth 2.0 login helper.
//!
//! Authorization Code + PKCE flow against Google's OIDC endpoints.
//!
//! The crate is intentionally agnostic about how state is stored between
//! the authorize redirect and the callback - the caller is responsible
//! for stashing the [`AuthorizationState`] in a signed cookie / session
//! / DB row, and for verifying that the `state` query param at callback
//! time matches what was persisted. [`Client::exchange_code`] only does
//! the OAuth/HTTPS work.
//!
//! # Configuration
//!
//! [`Config::from_env`] reads three required environment variables:
//!
//! - `GOOGLE_OAUTH_CLIENT_ID`
//! - `GOOGLE_OAUTH_CLIENT_SECRET`
//! - `GOOGLE_OAUTH_REDIRECT_URI`
//!
//! # Example
//!
//! ```no_run
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! let config = google_oauth_flow::Config::from_env()?;
//! let client = google_oauth_flow::Client::new(config);
//!
//! // 1. Build the authorize URL and persist the state.
//! let (authorize_url, state) = client.build_authorize_url()?;
//! // ... persist `state` (e.g. signed cookie) and 302 to `authorize_url`.
//!
//! // 2. On callback: verify state.csrf_token matches the `state` query
//! //    param yourself, then:
//! let userinfo = client
//!     .exchange_code("the_code_from_query", &state.pkce_verifier)
//!     .await?;
//! # Ok(()) }
//! ```

use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

/// Crate version from `Cargo.toml`.
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `git describe --tags --always --dirty` at build time. See `build.rs`.
pub const GIT_DESCRIBE: &str = env!("MOKOSH_GIT_DESCRIBE");

/// Short git commit hash captured at build time.
pub const GIT_HASH: &str = env!("MOKOSH_GIT_HASH");

/// ISO-8601 UTC build timestamp.
pub const BUILD_DATE: &str = env!("MOKOSH_BUILD_DATE");

/// OAuth credentials + redirect URI.
#[derive(Debug, Clone)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("environment variable {0} is missing or empty")]
    MissingEnv(&'static str),
}

impl Config {
    /// Read credentials from `GOOGLE_OAUTH_CLIENT_ID`,
    /// `GOOGLE_OAUTH_CLIENT_SECRET`, and `GOOGLE_OAUTH_REDIRECT_URI`.
    /// All three must be set and non-empty.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            client_id: required_env("GOOGLE_OAUTH_CLIENT_ID")?,
            client_secret: required_env("GOOGLE_OAUTH_CLIENT_SECRET")?,
            redirect_uri: required_env("GOOGLE_OAUTH_REDIRECT_URI")?,
        })
    }
}

fn required_env(key: &'static str) -> Result<String, ConfigError> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(ConfigError::MissingEnv(key)),
    }
}

/// Opaque state values the caller must persist between the authorize
/// redirect and the callback. Contains the CSRF token (compare against
/// the `state` query param at callback time) and the PKCE verifier
/// (passed back into [`Client::exchange_code`]).
#[derive(Debug, Clone)]
pub struct AuthorizationState {
    pub csrf_token: String,
    pub pkce_verifier: String,
}

/// Subset of Google's OIDC userinfo response.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleUserInfo {
    pub sub: String,
    pub email: String,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    /// Google Workspace hosted domain (only present for Workspace users).
    pub hd: Option<String>,
}

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("invalid URL in OAuth config: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("could not build HTTP client: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("invalid OAuth config: {0}")]
    Config(String),
    #[error("token exchange failed: {0}")]
    Token(String),
    #[error("userinfo HTTP failed: {0}")]
    Userinfo(#[from] reqwest::Error),
}

/// Type alias for the configured [`oauth2::basic::BasicClient`] after we
/// set the auth, token, and redirect endpoints. Keeps the verbose
/// typestate generics in one place.
type ConfiguredOAuthClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// The OAuth client. Holds the credentials and a reusable
/// [`reqwest::Client`]. Cheap to clone via `Arc` if you need to share
/// it across handlers.
pub struct Client {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl Client {
    /// Build a new client. The HTTP client has automatic redirects
    /// disabled per OAuth2 RFC 6749 best practice (auth code flows
    /// MUST NOT follow redirects).
    pub fn new(config: Config) -> Result<Self, BuildError> {
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_uri: config.redirect_uri,
            http,
        })
    }

    fn oauth(&self) -> Result<ConfiguredOAuthClient, BuildError> {
        Ok(BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(AUTH_URL.to_string())?)
            .set_token_uri(TokenUrl::new(TOKEN_URL.to_string())?)
            .set_redirect_uri(RedirectUrl::new(self.redirect_uri.clone())?))
    }

    /// Build the URL to redirect the browser to + the values the caller
    /// must persist and present back at the callback.
    pub fn build_authorize_url(&self) -> Result<(Url, AuthorizationState), BuildError> {
        let oauth = self.oauth()?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf) = oauth
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(challenge)
            .url();
        Ok((
            url,
            AuthorizationState {
                csrf_token: csrf.secret().to_owned(),
                pkce_verifier: verifier.secret().to_owned(),
            },
        ))
    }

    /// Exchange the authorization code for an access token, then fetch
    /// userinfo. The caller MUST verify the `state` query param matches
    /// the persisted [`AuthorizationState::csrf_token`] before invoking.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<GoogleUserInfo, ExchangeError> {
        let oauth = self
            .oauth()
            .map_err(|e| ExchangeError::Config(e.to_string()))?;

        let token = oauth
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
            .request_async(&self.http)
            .await
            .map_err(|e| ExchangeError::Token(e.to_string()))?;

        let resp = self
            .http
            .get(USERINFO_URL)
            .bearer_auth(token.access_token().secret())
            .send()
            .await?
            .error_for_status()?;

        Ok(resp.json().await?)
    }
}
