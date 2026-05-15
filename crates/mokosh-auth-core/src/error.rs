//! Auth errors. OIDC-spec error codes are preserved verbatim so the HTTP
//! layer can map directly to RFC 6749 / OIDC Core error responses without
//! re-stringifying.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    // --- OAuth 2.0 / OIDC error codes (RFC 6749, OIDC Core 3.1.2.6) ---
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    #[error("invalid_client")]
    InvalidClient,

    #[error("invalid_grant: {0}")]
    InvalidGrant(String),

    #[error("invalid_scope")]
    InvalidScope,

    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),

    #[error("unsupported_grant_type")]
    UnsupportedGrantType,

    #[error("unsupported_response_type")]
    UnsupportedResponseType,

    #[error("access_denied: {0}")]
    AccessDenied(String),

    #[error("login_required")]
    LoginRequired,

    #[error("interaction_required")]
    InteractionRequired,

    // --- Internal / non-protocol errors ---
    #[error("invalid redirect_uri")]
    InvalidRedirect,

    #[error("PKCE required (S256)")]
    PkceRequired,

    /// Refresh token reuse detected. Family is revoked. This is critical
    /// and triggers an alert.
    #[error("refresh token reuse detected")]
    ReuseDetected,

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("rate limited")]
    RateLimited,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("policy violation: {0}")]
    Policy(String),

    #[error("server_error: {0}")]
    Internal(String),
}

impl AuthError {
    /// Convenience constructor used at PKCE validation sites.
    pub fn pkce_required() -> Self {
        Self::PkceRequired
    }

    /// Maps to the spec error string used in OAuth error responses.
    pub fn oauth_code(&self) -> &'static str {
        use AuthError::*;
        match self {
            InvalidRequest(_) | InvalidRedirect | PkceRequired => "invalid_request",
            InvalidClient => "invalid_client",
            InvalidGrant(_) | ReuseDetected => "invalid_grant",
            InvalidScope => "invalid_scope",
            UnauthorizedClient(_) => "unauthorized_client",
            UnsupportedGrantType => "unsupported_grant_type",
            UnsupportedResponseType => "unsupported_response_type",
            AccessDenied(_) => "access_denied",
            LoginRequired => "login_required",
            InteractionRequired => "interaction_required",
            _ => "server_error",
        }
    }
}
