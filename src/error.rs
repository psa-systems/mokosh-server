//! Core error types for Mokosh Server

use thiserror::Error;

/// Core error type for Mokosh Server
#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Tenant not found: {0}")]
    TenantNotFound(String),

    #[error("Tenant suspended: {0}")]
    TenantSuspended(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("External service error: {0}")]
    ExternalService(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl CoreError {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            CoreError::AuthenticationFailed(_) => 401,
            CoreError::AuthorizationDenied(_) => 403,
            CoreError::NotFound(_) => 404,
            CoreError::Validation(_) => 400,
            CoreError::TenantNotFound(_) => 404,
            CoreError::TenantSuspended(_) => 403,
            CoreError::RateLimitExceeded => 429,
            CoreError::Database(_) => 500,
            CoreError::Configuration(_) => 500,
            CoreError::ExternalService(_) => 502,
            CoreError::Internal(_) => 500,
        }
    }

    /// Check if this is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        self.status_code() >= 400 && self.status_code() < 500
    }

    /// Check if this is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        self.status_code() >= 500
    }
}

#[cfg(feature = "server")]
impl From<sqlx::Error> for CoreError {
    fn from(err: sqlx::Error) -> Self {
        CoreError::Database(err.to_string())
    }
}

#[cfg(feature = "server")]
impl axum::response::IntoResponse for CoreError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;

        let status =
            StatusCode::from_u16(self.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        let body = serde_json::json!({
            "error": self.to_string(),
            "code": self.status_code(),
        });

        (status, Json(body)).into_response()
    }
}

/// Result type alias using CoreError
pub type Result<T> = std::result::Result<T, CoreError>;
