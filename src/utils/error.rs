//! Error handling for Mokosh Server
//!
//! Provides a unified error type that works across server and client.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result type alias for application errors
pub type AppResult<T> = Result<T, AppError>;

/// Application error types
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum AppError {
    /// Authentication error - user not logged in
    #[error("Authentication required")]
    Unauthorized,

    /// Authorization error - user doesn't have permission
    #[error("Access denied: {0}")]
    Forbidden(String),

    /// Resource not found
    #[error("{0} not found")]
    NotFound(String),

    /// Validation error with field-level details
    #[error("Validation failed: {message}")]
    Validation {
        message: String,
        errors: Vec<FieldError>,
    },

    /// Duplicate resource error
    #[error("{0} already exists")]
    Conflict(String),

    /// Bad request with message
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded. Please try again later.")]
    RateLimited,

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// External service error
    #[error("External service error: {service} - {message}")]
    ExternalService { service: String, message: String },

    /// Internal server error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Tenant-related errors (multi-tenant mode)
    #[error("Tenant error: {0}")]
    Tenant(String),

    /// File/attachment error
    #[error("File error: {0}")]
    File(String),

    /// Email error
    #[error("Email error: {0}")]
    Email(String),

    /// Payment/billing error
    #[error("Payment error: {0}")]
    Payment(String),

    /// Integration error (RMM, etc.)
    #[error("Integration error: {0}")]
    Integration(String),
}

/// Field-level validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldError {
    pub field: String,
    pub message: String,
    pub code: String,
}

impl FieldError {
    pub fn new(
        field: impl Into<String>,
        message: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            code: code.into(),
        }
    }
}

impl AppError {
    /// Create a validation error with field errors
    pub fn validation(message: impl Into<String>, errors: Vec<FieldError>) -> Self {
        Self::Validation {
            message: message.into(),
            errors,
        }
    }

    /// Create a validation error for a single field
    pub fn validation_field(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            message: "Validation failed".to_string(),
            errors: vec![FieldError::new(field, message, "invalid")],
        }
    }

    /// Create a not found error
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound(resource.into())
    }

    /// Create a forbidden error
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    /// Create a conflict error
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// Create a database error
    pub fn database(message: impl Into<String>) -> Self {
        Self::Database(message.into())
    }

    /// Create an external service error
    pub fn external_service(service: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ExternalService {
            service: service.into(),
            message: message.into(),
        }
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::Validation { .. } => 422,
            Self::Conflict(_) => 409,
            Self::BadRequest(_) => 400,
            Self::RateLimited => 429,
            Self::Database(_) => 500,
            Self::ExternalService { .. } => 502,
            Self::Internal(_) => 500,
            Self::Configuration(_) => 500,
            Self::Tenant(_) => 400,
            Self::File(_) => 400,
            Self::Email(_) => 500,
            Self::Payment(_) => 402,
            Self::Integration(_) => 502,
        }
    }

    /// Get the error code for API responses
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Validation { .. } => "VALIDATION_ERROR",
            Self::Conflict(_) => "CONFLICT",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::RateLimited => "RATE_LIMITED",
            Self::Database(_) => "DATABASE_ERROR",
            Self::ExternalService { .. } => "EXTERNAL_SERVICE_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::Configuration(_) => "CONFIGURATION_ERROR",
            Self::Tenant(_) => "TENANT_ERROR",
            Self::File(_) => "FILE_ERROR",
            Self::Email(_) => "EMAIL_ERROR",
            Self::Payment(_) => "PAYMENT_ERROR",
            Self::Integration(_) => "INTEGRATION_ERROR",
        }
    }
}

/// API error response format
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<FieldError>>,
}

impl From<AppError> for ErrorResponse {
    fn from(error: AppError) -> Self {
        let errors = match &error {
            AppError::Validation { errors, .. } => Some(errors.clone()),
            _ => None,
        };

        Self {
            error: ErrorDetail {
                code: error.error_code().to_string(),
                message: error.to_string(),
                errors,
            },
        }
    }
}

// Server-side conversions
#[cfg(feature = "server")]
mod server_impl {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::Json;

    impl IntoResponse for AppError {
        fn into_response(self) -> Response {
            let status = StatusCode::from_u16(self.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            let body = ErrorResponse::from(self);

            (status, Json(body)).into_response()
        }
    }

    impl From<sqlx::Error> for AppError {
        fn from(err: sqlx::Error) -> Self {
            match err {
                sqlx::Error::RowNotFound => Self::NotFound("Record".to_string()),
                sqlx::Error::Database(db_err) => {
                    // Check for unique constraint violations
                    if let Some(code) = db_err.code() {
                        if code == "23505" {
                            return Self::Conflict("Record already exists".to_string());
                        }
                    }
                    // Log the actual error but return a generic message
                    tracing::error!("Database error: {:?}", db_err);
                    Self::Database("Database operation failed".to_string())
                }
                _ => {
                    tracing::error!("Database error: {:?}", err);
                    Self::Database("Database operation failed".to_string())
                }
            }
        }
    }

    impl From<jsonwebtoken::errors::Error> for AppError {
        fn from(err: jsonwebtoken::errors::Error) -> Self {
            tracing::warn!("JWT error: {:?}", err);
            Self::Unauthorized
        }
    }

    impl From<argon2::password_hash::Error> for AppError {
        fn from(err: argon2::password_hash::Error) -> Self {
            tracing::error!("Password hash error: {:?}", err);
            Self::Internal("Password operation failed".to_string())
        }
    }

    impl From<lettre::error::Error> for AppError {
        fn from(err: lettre::error::Error) -> Self {
            tracing::error!("Email error: {:?}", err);
            Self::Email(format!("Failed to send email: {}", err))
        }
    }

    impl From<lettre::transport::smtp::Error> for AppError {
        fn from(err: lettre::transport::smtp::Error) -> Self {
            tracing::error!("SMTP error: {:?}", err);
            Self::Email(format!("SMTP error: {}", err))
        }
    }

    impl From<reqwest::Error> for AppError {
        fn from(err: reqwest::Error) -> Self {
            tracing::error!("HTTP client error: {:?}", err);
            Self::ExternalService {
                service: "HTTP".to_string(),
                message: err.to_string(),
            }
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let field_errors: Vec<FieldError> = errors
            .field_errors()
            .iter()
            .flat_map(|(field, errs)| {
                errs.iter().map(|e| {
                    FieldError::new(
                        field.to_string(),
                        e.message.clone().unwrap_or_default().to_string(),
                        e.code.to_string(),
                    )
                })
            })
            .collect();

        Self::Validation {
            message: "Validation failed".to_string(),
            errors: field_errors,
        }
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::BadRequest(format!("JSON error: {}", err))
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        Self::File(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_error_status_codes() {
        assert_eq!(AppError::Unauthorized.status_code(), 401);
        assert_eq!(AppError::Forbidden("test".to_string()).status_code(), 403);
        assert_eq!(AppError::NotFound("test".to_string()).status_code(), 404);
        assert_eq!(
            AppError::Validation {
                message: "test".to_string(),
                errors: vec![]
            }
            .status_code(),
            422
        );
        assert_eq!(AppError::Conflict("test".to_string()).status_code(), 409);
        assert_eq!(AppError::BadRequest("test".to_string()).status_code(), 400);
        assert_eq!(AppError::RateLimited.status_code(), 429);
        assert_eq!(AppError::Payment("test".to_string()).status_code(), 402);
    }

    #[test]
    fn test_app_error_codes() {
        assert_eq!(AppError::Unauthorized.error_code(), "UNAUTHORIZED");
        assert_eq!(
            AppError::Forbidden("test".to_string()).error_code(),
            "FORBIDDEN"
        );
        assert_eq!(
            AppError::NotFound("test".to_string()).error_code(),
            "NOT_FOUND"
        );
        assert_eq!(AppError::RateLimited.error_code(), "RATE_LIMITED");
    }

    #[test]
    fn test_field_error_creation() {
        let error = FieldError::new("email", "Invalid email", "invalid_email");
        assert_eq!(error.field, "email");
        assert_eq!(error.message, "Invalid email");
        assert_eq!(error.code, "invalid_email");
    }

    #[test]
    fn test_validation_error_creation() {
        let error = AppError::validation(
            "Form validation failed",
            vec![FieldError::new("email", "Required", "required")],
        );

        match error {
            AppError::Validation { message, errors } => {
                assert_eq!(message, "Form validation failed");
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].field, "email");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_validation_field_error() {
        let error = AppError::validation_field("username", "Username is required");

        match error {
            AppError::Validation { message, errors } => {
                assert_eq!(message, "Validation failed");
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].field, "username");
                assert_eq!(errors[0].message, "Username is required");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_not_found_error() {
        let error = AppError::not_found("User");
        match error {
            AppError::NotFound(resource) => assert_eq!(resource, "User"),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_error_display() {
        let error = AppError::NotFound("Ticket".to_string());
        assert_eq!(error.to_string(), "Ticket not found");

        let forbidden = AppError::Forbidden("You cannot access this resource".to_string());
        assert_eq!(
            forbidden.to_string(),
            "Access denied: You cannot access this resource"
        );
    }

    #[test]
    fn test_error_response_from_app_error() {
        let error = AppError::Validation {
            message: "Validation failed".to_string(),
            errors: vec![FieldError::new("email", "Invalid", "invalid")],
        };
        let response = ErrorResponse::from(error);

        assert_eq!(response.error.code, "VALIDATION_ERROR");
        assert!(response.error.errors.is_some());
        assert_eq!(response.error.errors.unwrap().len(), 1);
    }

    #[test]
    fn test_error_response_without_field_errors() {
        let error = AppError::Unauthorized;
        let response = ErrorResponse::from(error);

        assert_eq!(response.error.code, "UNAUTHORIZED");
        assert!(response.error.errors.is_none());
    }

    #[test]
    fn test_external_service_error() {
        let error = AppError::external_service("Stripe", "Payment failed");
        match error {
            AppError::ExternalService { service, message } => {
                assert_eq!(service, "Stripe");
                assert_eq!(message, "Payment failed");
            }
            _ => panic!("Expected ExternalService error"),
        }
    }
}
