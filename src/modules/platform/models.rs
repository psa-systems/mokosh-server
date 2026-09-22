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
    /// TOTP code; required when the admin has MFA enabled.
    #[serde(default)]
    pub mfa_code: Option<String>,
    /// PMS-1300: a single-use recovery code, for the operator who lost
    /// the authenticator. Spends the code on match; a `mfa_code` alongside
    /// wins so a live TOTP does not consume a recovery.
    #[serde(default)]
    pub recovery_code: Option<String>,
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

/// `POST /api/v1/platform/me/mfa/setup` body. PMS-1300: current password
/// is re-verified inline so a stolen access token cannot enrol an
/// attacker's authenticator.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PlatformMfaSetupRequest {
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,
}

/// `POST /api/v1/platform/me/mfa/setup` response. Same shape the contact
/// plane returns: the base32 secret plus a ready-to-scan otpauth URI, so
/// the SPA does not have to compose the URI itself.
#[derive(Debug, Clone, Serialize)]
pub struct PlatformMfaSetupResponse {
    pub secret: String,
    pub provisioning_uri: String,
}

/// `POST /api/v1/platform/me/mfa/enable` body. PMS-1300: the live TOTP
/// code the operator sees on their authenticator, plus the same
/// current-password re-auth as setup.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PlatformMfaEnableRequest {
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,
    #[validate(length(min = 6, message = "TOTP code is required"))]
    pub code: String,
}

/// `POST /api/v1/platform/me/mfa/enable` response. PMS-1300: the plaintext
/// recovery codes, returned to the operator EXACTLY ONCE. The server keeps
/// only their hashes; a lost list cannot be reissued from what is stored.
#[derive(Debug, Clone, Serialize)]
pub struct PlatformMfaEnableResponse {
    pub recovery_codes: Vec<String>,
}

/// `POST /api/v1/platform/me/mfa/disable` body. PMS-1300: needs the current
/// password AND a live second factor (TOTP or an unspent recovery code), so
/// a stolen access token cannot quietly weaken the account.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PlatformMfaDisableRequest {
    #[validate(length(min = 1, message = "Current password is required"))]
    pub current_password: String,
    /// TOTP or recovery code; the digit-only form is treated as TOTP.
    #[validate(length(min = 6, message = "MFA code is required"))]
    pub code: String,
}
