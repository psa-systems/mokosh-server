//! Map [`AuthError`] to HTTP responses.
//!
//! For `/oauth2/*` endpoints we follow RFC 6749 / OIDC Core: emit the
//! exact `error` code in a JSON body. For `/v1/auth/*` endpoints we use
//! conventional REST status codes with a small JSON envelope.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use mokosh_auth_core::AuthError;
use serde::Serialize;

#[derive(Debug)]
pub struct HttpError(pub AuthError);

impl From<AuthError> for HttpError {
    fn from(e: AuthError) -> Self {
        Self(e)
    }
}

#[derive(Serialize)]
struct OAuthErrorBody {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let (status, body) = oauth_status_and_body(&self.0);
        // Always log 5xx with the underlying AuthError so operators can
        // diagnose `server_error` responses; the response body deliberately
        // omits the detail to avoid leaking internals to clients.
        if status.is_server_error() {
            tracing::error!(
                error_code = body.error,
                error_detail = ?self.0,
                "mokosh-auth-http 5xx"
            );
        }
        let json = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        (
            status,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            json,
        )
            .into_response()
    }
}

fn oauth_status_and_body(err: &AuthError) -> (StatusCode, OAuthErrorBody) {
    use AuthError::*;
    let status = match err {
        InvalidClient => StatusCode::UNAUTHORIZED,
        AccessDenied(_) => StatusCode::UNAUTHORIZED,
        LoginRequired | InteractionRequired => StatusCode::UNAUTHORIZED,
        Forbidden(_) => StatusCode::FORBIDDEN,
        NotFound => StatusCode::NOT_FOUND,
        Conflict(_) => StatusCode::CONFLICT,
        RateLimited => StatusCode::TOO_MANY_REQUESTS,
        Internal(_) | Storage(_) | Crypto(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    // Description: include only safe text. We avoid surfacing internal
    // error contents for InvalidClient/AccessDenied to prevent oracle
    // attacks.
    let description = match err {
        AuthError::InvalidClient | AuthError::AccessDenied(_) => None,
        AuthError::Internal(_) | AuthError::Storage(_) | AuthError::Crypto(_) => None,
        other => Some(other.to_string()),
    };
    (
        status,
        OAuthErrorBody {
            error: err.oauth_code(),
            error_description: description,
        },
    )
}
