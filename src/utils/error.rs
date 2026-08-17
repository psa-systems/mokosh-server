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

    /// Resource is gone - the target existed but is no longer usable
    /// (e.g. a one-time token that was already redeemed). 410 Gone.
    #[error("Gone: {0}")]
    Gone(String),

    /// The authenticated principal's user row is soft-deleted (Bunyip
    /// account_deleted webhook has tombstoned them). 410 Gone with the
    /// distinct code `ACCOUNT_DELETED` so the SPA can catch it in its
    /// shared fetch layer and render a terminal "your account has been
    /// deleted" modal instead of degrading to the generic offline banner
    /// on repeated 401s. See MAPPS-348.
    #[error("Account has been deleted.")]
    AccountDeleted,

    /// A Bearer credential was presented and rejected because it had
    /// expired. 401 with the distinct code `TOKEN_EXPIRED` (PMS-769) so a
    /// client can tell "renew your token" apart from "you sent no
    /// credential" without string-matching the message. Only the auth
    /// extractors raise it; every other 401 stays `Unauthorized`.
    #[error("Your session has expired.")]
    TokenExpired,

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

    /// Request body too large. 413 Payload Too Large; used by the
    /// PMS-483 attachment upload surface to reject oversize blobs
    /// before they hit disk.
    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),

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
        // The `Validation` Display prefixes "Validation failed: ", so this
        // message must not repeat that phrase (PMS-298).
        Self::Validation {
            message: "one or more fields are invalid".to_string(),
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
            Self::Gone(_) => 410,
            Self::AccountDeleted => 410,
            Self::TokenExpired => 401,
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
            Self::PayloadTooLarge(_) => 413,
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
            Self::Gone(_) => "GONE",
            Self::AccountDeleted => "ACCOUNT_DELETED",
            Self::TokenExpired => "TOKEN_EXPIRED",
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
            Self::PayloadTooLarge(_) => "PAYLOAD_TOO_LARGE",
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
pub use server_impl::normalize_error_envelope;

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

    /// Map an extractor-rejection status to the canonical `{error:{code,message}}`
    /// envelope. The original rejection body (raw axum/serde plaintext) is
    /// discarded so internal serde detail, field names, and line/column offsets
    /// never leak (PMS-298).
    fn envelope_for_rejection(status: StatusCode) -> ErrorResponse {
        let (code, message) = match status {
            StatusCode::BAD_REQUEST => (
                "BAD_REQUEST",
                "The request was malformed or could not be read.",
            ),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => (
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json.",
            ),
            StatusCode::PAYLOAD_TOO_LARGE => {
                ("PAYLOAD_TOO_LARGE", "The request body is too large.")
            }
            StatusCode::LENGTH_REQUIRED => {
                ("LENGTH_REQUIRED", "A Content-Length header is required.")
            }
            // axum returns 422 when a JSON body fails to deserialize into the
            // target type (missing field, wrong type, unknown enum variant).
            StatusCode::UNPROCESSABLE_ENTITY => (
                "BAD_REQUEST",
                "The request body did not match the expected format.",
            ),
            StatusCode::METHOD_NOT_ALLOWED => (
                "METHOD_NOT_ALLOWED",
                "This method is not allowed for this resource.",
            ),
            _ => ("BAD_REQUEST", "The request could not be processed."),
        };
        ErrorResponse {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
                errors: None,
            },
        }
    }

    /// Axum middleware that rewrites raw extractor-rejection responses (which
    /// arrive as `text/plain`) into the standard JSON error envelope so every
    /// 4xx the API surface emits shares the `{error:{code,message}}` shape and
    /// no raw "Failed to deserialize the JSON body..." plaintext is ever
    /// returned to a client (PMS-298). Responses that are already JSON (every
    /// `AppError`, including structured validation errors) pass through
    /// untouched.
    pub async fn normalize_error_envelope(
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> Response {
        let response = next.run(request).await;
        let status = response.status();
        if !status.is_client_error() {
            return response;
        }
        let is_json = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.starts_with("application/json"))
            .unwrap_or(false);
        if is_json {
            return response;
        }
        // Non-JSON 4xx: an extractor rejection (or similar) leaked through.
        // Replace it with the canonical envelope, discarding the raw body.
        (status, Json(envelope_for_rejection(status))).into_response()
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

/// Render a `serde_json::Value` constraint bound (min/max/equal) as a plain
/// number string. `validator` stores these params as JSON numbers (often
/// `f64`), so an integer bound like `255` would otherwise print as `255.0`.
fn format_bound(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 {
                    (f as i64).to_string()
                } else {
                    f.to_string()
                }
            } else {
                n.to_string()
            }
        }
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Build a human-readable message for a single `validator` field error.
///
/// `validator` leaves `message` as `None` unless the field carries an explicit
/// `message = "..."` attribute, which is why the raw conversion previously
/// emitted an empty per-field `message` (PMS-298). When no explicit message is
/// present we synthesise one from the failing constraint's code and params so
/// the response states what was wrong and includes the constraint bound (e.g.
/// the max length).
fn humanize_field_error(error: &validator::ValidationError) -> String {
    if let Some(message) = &error.message {
        return message.to_string();
    }

    let bound = |key: &str| error.params.get(key).map(format_bound);
    let (min, max, equal) = (bound("min"), bound("max"), bound("equal"));

    match error.code.as_ref() {
        "length" => match (equal, min, max) {
            (Some(equal), _, _) => format!("must be exactly {equal} characters"),
            (_, Some(min), Some(max)) => {
                format!("must be between {min} and {max} characters")
            }
            (_, Some(min), None) => format!("must be at least {min} characters"),
            (_, None, Some(max)) => format!("must be at most {max} characters"),
            _ => "has an invalid length".to_string(),
        },
        "range" => match (min, max) {
            (Some(min), Some(max)) => format!("must be between {min} and {max}"),
            (Some(min), None) => format!("must be at least {min}"),
            (None, Some(max)) => format!("must be at most {max}"),
            _ => "is out of range".to_string(),
        },
        "email" => "must be a valid email address".to_string(),
        "url" => "must be a valid URL".to_string(),
        "required" | "required_nested" => "is required".to_string(),
        "must_match" => "does not match the expected value".to_string(),
        "contains" => "is missing required content".to_string(),
        "does_not_contain" => "contains a disallowed value".to_string(),
        "regex" => "is not in the expected format".to_string(),
        "credit_card" => "must be a valid credit card number".to_string(),
        "phone" => "must be a valid phone number".to_string(),
        "non_control_character" => "must not contain control characters".to_string(),
        other => format!("failed the '{other}' validation"),
    }
}

/// Extract the form field a schema-level (cross-field) validation error should
/// attach to, if the rule recorded one via `validation::cross_field_error`.
///
/// validator-crate keys schema rules under the `__all__` bucket; this lets the
/// conversion re-key the error onto the named field so the client can render it
/// inline (PMS-364). Returns `None` for ordinary single-field errors, which are
/// already keyed on their field.
fn cross_field_target(error: &validator::ValidationError) -> Option<String> {
    error
        .params
        .get(crate::utils::validation::CROSS_FIELD_TARGET_PARAM)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

impl From<validator::ValidationErrors> for AppError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let mut field_errors = Vec::new();
        flatten_validation_errors(&errors, "", &mut field_errors);

        // The `Validation` Display already prefixes "Validation failed: ", so
        // the message here must not repeat it (PMS-298: the old "Validation
        // failed" value produced "Validation failed: Validation failed").
        Self::Validation {
            message: "one or more fields are invalid".to_string(),
            errors: field_errors,
        }
    }
}

/// Recursively flatten a `validator::ValidationErrors` tree into a flat list of
/// `FieldError`s. Nested struct/list errors produced by `#[validate(nested)]`
/// land under `ValidationErrorsKind::Struct` / `::List`, which the old top-level
/// `field_errors()` flatten silently dropped, so a 422 for a bad nested field
/// (e.g. `address.country`) arrived with an empty `errors[]` (PMS-330). Each
/// child field path is prefixed with the dotted (and `[index]`-suffixed for
/// list elements) path accumulated in `prefix` so clients can map the error to
/// the offending input. `prefix` is "" at the root.
fn flatten_validation_errors(
    errors: &validator::ValidationErrors,
    prefix: &str,
    out: &mut Vec<FieldError>,
) {
    for (field, kind) in errors.errors() {
        match kind {
            validator::ValidationErrorsKind::Field(errs) => {
                for e in errs {
                    // Schema-level (cross-field) rules are keyed under
                    // validator-crate's `__all__` bucket, which the client
                    // cannot bind to a form field. When the rule recorded a
                    // target field (see `validation::cross_field_error`),
                    // re-key the error onto that field so the form renders it
                    // inline instead of as a generic banner (PMS-364).
                    let target = cross_field_target(e).unwrap_or_else(|| field.to_string());
                    let path = join_field_path(prefix, &target);
                    out.push(FieldError::new(
                        path,
                        humanize_field_error(e),
                        e.code.to_string(),
                    ));
                }
            }
            validator::ValidationErrorsKind::Struct(nested) => {
                let path = join_field_path(prefix, field);
                flatten_validation_errors(nested, &path, out);
            }
            validator::ValidationErrorsKind::List(items) => {
                let base = join_field_path(prefix, field);
                for (index, nested) in items {
                    let path = format!("{base}[{index}]");
                    flatten_validation_errors(nested, &path, out);
                }
            }
        }
    }
}

/// Join a dotted field path. Returns `field` unchanged at the root (empty
/// `prefix`), otherwise `prefix.field`.
fn join_field_path(prefix: &str, field: &str) -> String {
    if prefix.is_empty() {
        field.to_string()
    } else {
        format!("{prefix}.{field}")
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
        assert_eq!(AppError::AccountDeleted.status_code(), 410);
        // PMS-769: RFC 6750 puts an expired bearer at 401, not 403.
        assert_eq!(AppError::TokenExpired.status_code(), 401);
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
        assert_eq!(AppError::AccountDeleted.error_code(), "ACCOUNT_DELETED");
        // PMS-769: the stable machine-readable code the SPA branches on.
        assert_eq!(AppError::TokenExpired.error_code(), "TOKEN_EXPIRED");
        assert_eq!(
            AppError::TokenExpired.to_string(),
            "Your session has expired."
        );
    }

    /// PMS-769: the RFC 6750 challenge is attached by the auth extractors'
    /// `AuthRejection`, never by `AppError` itself. The webhook HMAC gates
    /// (`bunyip_webhook.rs`, `stripe_webhook.rs`) and the portal password
    /// checks (`portal/service.rs`) return `AppError::Unauthorized` straight
    /// out of an `AppResult` handler, so this is the exact response they
    /// render: a plain `UNAUTHORIZED` envelope with no `WWW-Authenticate`.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn unauthorized_response_carries_no_bearer_challenge() {
        use axum::response::IntoResponse;

        for error in [AppError::Unauthorized, AppError::TokenExpired] {
            let response = error.into_response();
            assert_eq!(response.status(), 401);
            assert!(
                response.headers().get("www-authenticate").is_none(),
                "AppError must not attach a bearer challenge on its own"
            );
        }
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
                // No longer the literal "Validation failed": the Display impl
                // prefixes that phrase, so storing it here doubled it (PMS-298).
                assert_eq!(message, "one or more fields are invalid");
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].field, "username");
                assert_eq!(errors[0].message, "Username is required");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_validation_message_not_doubled() {
        // PMS-298: the top-level message must not read "Validation failed:
        // Validation failed".
        let error = AppError::validation_field("username", "Username is required");
        assert_eq!(
            error.to_string(),
            "Validation failed: one or more fields are invalid"
        );
    }

    #[test]
    fn test_humanize_length_includes_bound() {
        // PMS-298: a `length(max = 255)` failure with no explicit message must
        // produce a non-empty, human-readable message that names the bound.
        let mut err = validator::ValidationError::new("length");
        err.add_param("max".into(), &255u64);
        let message = humanize_field_error(&err);
        assert!(message.contains("255"), "message was {message:?}");
        assert!(message.contains("at most"), "message was {message:?}");
        assert!(!message.is_empty());
    }

    #[test]
    fn test_humanize_respects_explicit_message() {
        let mut err = validator::ValidationError::new("length");
        err.message = Some("Name is too long".into());
        assert_eq!(humanize_field_error(&err), "Name is too long");
    }

    #[test]
    fn test_validation_errors_conversion_populates_messages() {
        // Round-trip a real `validator` failure (length max on `name`) and
        // confirm the per-field message is non-empty (PMS-298).
        use validator::Validate;

        #[derive(Validate)]
        struct Demo {
            #[validate(length(max = 3))]
            name: String,
        }

        let errs = Demo {
            name: "too long".to_string(),
        }
        .validate()
        .unwrap_err();

        let app_error = AppError::from(errs);
        match app_error {
            AppError::Validation { message, errors } => {
                assert_eq!(message, "one or more fields are invalid");
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].field, "name");
                assert_eq!(errors[0].code, "length");
                assert!(!errors[0].message.is_empty(), "per-field message was empty");
                assert!(
                    errors[0].message.contains('3'),
                    "bound missing: {:?}",
                    errors[0].message
                );
            }
            other => panic!("Expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_cross_field_error_rekeyed_to_named_field() {
        // PMS-364: a schema-level rule built via `cross_field_error` lands in
        // validator-crate's `__all__` bucket, but the conversion must re-key
        // it onto the named field so the client can render it inline.
        use validator::Validate;

        fn check_range(req: &Demo) -> Result<(), validator::ValidationError> {
            if req.end < req.start {
                return Err(crate::utils::validation::cross_field_error(
                    "invalid_date_range",
                    "end",
                    "end must be on or after start",
                ));
            }
            Ok(())
        }

        #[derive(Validate)]
        #[validate(schema(function = check_range))]
        struct Demo {
            start: i32,
            end: i32,
        }

        let errs = Demo { start: 5, end: 1 }.validate().unwrap_err();
        // Sanity: validator keyed it under `__all__`, not the target field.
        assert!(errs.field_errors().contains_key("__all__"));

        match AppError::from(errs) {
            AppError::Validation { errors, .. } => {
                assert_eq!(errors.len(), 1);
                // Re-keyed onto the named field, not left as `__all__`.
                assert_eq!(errors[0].field, "end");
                assert_eq!(errors[0].code, "invalid_date_range");
                assert_eq!(errors[0].message, "end must be on or after start");
            }
            other => panic!("Expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_single_field_error_not_rekeyed() {
        // A plain single-field error has no target param and must keep its own
        // field key (no regression on the phone-validator pattern, PMS-364).
        use validator::Validate;

        #[derive(Validate)]
        struct Demo {
            #[validate(length(max = 3))]
            name: String,
        }

        let errs = Demo {
            name: "too long".to_string(),
        }
        .validate()
        .unwrap_err();

        match AppError::from(errs) {
            AppError::Validation { errors, .. } => {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].field, "name");
            }
            other => panic!("Expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_nested_validation_errors_surface_with_dotted_path() {
        // PMS-330: a `#[validate(nested)]` struct field lands under
        // `ValidationErrorsKind::Struct`, which the old top-level flatten
        // dropped (empty `errors[]`). The recursion must surface each offending
        // nested field with a dotted path, while a `#[validate(nested)]` list
        // field uses an `[index]`-suffixed path.
        use validator::Validate;

        #[derive(Validate)]
        struct Address {
            #[validate(length(max = 2))]
            country: String,
            #[validate(length(max = 5))]
            postal_code: String,
        }

        #[derive(Validate)]
        struct Company {
            #[validate(length(max = 3))]
            name: String,
            #[validate(nested)]
            address: Address,
            #[validate(nested)]
            sites: Vec<Address>,
        }

        let errs = Company {
            name: "ok".to_string(),
            address: Address {
                country: "USA".to_string(),
                postal_code: "way-too-long".to_string(),
            },
            sites: vec![Address {
                country: "ok".to_string(),
                postal_code: "also-too-long".to_string(),
            }],
        }
        .validate()
        .unwrap_err();

        match AppError::from(errs) {
            AppError::Validation { errors, .. } => {
                let fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
                assert!(
                    fields.contains(&"address.country"),
                    "missing dotted nested path: {fields:?}"
                );
                assert!(
                    fields.contains(&"address.postal_code"),
                    "missing dotted nested path: {fields:?}"
                );
                assert!(
                    fields.contains(&"sites[0].postal_code"),
                    "missing indexed list path: {fields:?}"
                );
                // Nested messages are populated, not empty.
                for e in &errors {
                    assert!(!e.message.is_empty(), "empty nested message: {:?}", e.field);
                }
            }
            other => panic!("Expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_format_bound_trims_trailing_zero() {
        let value = serde_json::json!(255.0);
        assert_eq!(format_bound(&value), "255");
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
