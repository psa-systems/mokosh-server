//! MAPPS-513: request/response types for `/api/v1/platform` endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// `POST /api/v1/platform/login` body.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PlatformLoginRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// `POST /api/v1/platform/login` response. Mirrors the shape of
/// `LoginResponse` for the identity-plane path so the client's
/// install_session closures can be reused.
#[derive(Debug, Clone, Serialize)]
pub struct PlatformLoginResponse {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    pub admin: PlatformAdminProfile,
}

/// Public shape of a platform admin returned by the login handler.
/// Never includes password_hash or mfa_secret.
#[derive(Debug, Clone, Serialize)]
pub struct PlatformAdminProfile {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub mfa_enabled: bool,
}

/// `PUT /api/v1/platform/me/password` body.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PlatformChangePasswordRequest {
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,
    #[validate(length(min = 12, message = "New password must be at least 12 characters"))]
    pub new_password: String,
    #[validate(length(min = 12, message = "Confirmation must match"))]
    pub confirm_password: String,
}
