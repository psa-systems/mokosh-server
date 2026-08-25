//! mokosh-contact-login prompt 004: DTOs for the `/api/v1/contact/*`
//! plane.
//!
//! Wire shapes only. `ContactSession` is a request-extension type the
//! middleware inserts; the rest are HTTP request/response bodies.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// mokosh-contact-login prompt 004: authenticated contact snapshot the
/// contact-plane middleware attaches to every /api/v1/contact/* request
/// extension. Extractors (`RequireContactAuth`) hand this to route
/// handlers.
///
/// Distinct from `crate::modules::auth::CurrentUser` (staff plane) so
/// a staff-plane extractor cannot silently pick up a contact bearer +
/// vice versa. The JWT `typ` claim is checked before this row lands.
#[derive(Debug, Clone)]
pub struct ContactSession {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub company_id: Uuid,
    pub email: String,
    /// The union of every assigned role's capability set at the moment
    /// the JWT was minted. Belt-and-braces: privileged mutation
    /// endpoints re-load the effective set from `portal_roles` per
    /// request so a role revoke lands within one tick (prompt 008
    /// enforces this on the mutation paths).
    pub caps: Vec<String>,
    /// `contact_sessions.id` - the refresh-token session row this
    /// access token was minted from. Used by the logout + rotate paths.
    pub sid: Uuid,
}

/// JWT claims for the `typ: "contact"` token. Mirrors the shape of the
/// pre-pivot portal token but with a fresh `typ` string so a staff
/// verifier cannot accept it + vice versa.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactJwtClaims {
    pub sub: Uuid,
    pub tid: Uuid,
    pub cid: Uuid,
    pub email: String,
    pub caps: Vec<String>,
    pub sid: Uuid,
    #[serde(rename = "typ")]
    pub token_type: String,
    pub iat: i64,
    pub exp: i64,
}

/// Request body for `POST /api/v1/contact/auth/login`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactLoginRequest {
    #[validate(length(min = 1, max = 64, message = "portal slug is required"))]
    pub slug: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1, message = "password is required"))]
    pub password: String,
    /// TOTP code, sent on the second attempt after a `mfa_required`
    /// response. `contact.portal_mfa_secret` verifies it. Optional
    /// today (MFA is off by default on contacts); reserved for a
    /// follow-up ticket that adds the enrol flow.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

/// Response body for `POST /api/v1/contact/auth/login` +
/// `POST /api/v1/contact/auth/refresh`.
///
/// `contact` is populated on the full-session return; `mfa_required =
/// true` returns everything else empty so the SPA re-prompts for a
/// TOTP code (mirrors the staff-side pre-signal shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactLoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub contact: Option<ContactMe>,
    #[serde(default)]
    pub mfa_required: bool,
}

/// Response body for `GET /api/v1/contact/auth/me`.
///
/// Enough to render the top-bar + sidebar + capability gates in one
/// round-trip after a cold-load (or a `refresh` that returns).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactMe {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub company_id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub company_name: String,
    pub portal_slug: String,
    pub roles: Vec<ContactRoleSnippet>,
    pub caps: Vec<String>,
    #[serde(default)]
    pub mfa_enabled: bool,
}

/// One row inside `ContactMe.roles`. Distinct from the staff-plane
/// `PortalRoleSummary` shape which carries `capabilities` and
/// `is_builtin`; contacts only need the display name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactRoleSnippet {
    pub id: Uuid,
    pub name: String,
}

/// Request body for `POST /api/v1/contact/auth/refresh`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactRefreshRequest {
    #[validate(length(min = 1, message = "refresh token is required"))]
    pub refresh_token: String,
}

/// Request body for `POST /api/v1/contact/auth/logout`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactLogoutRequest {
    #[validate(length(min = 1, message = "refresh token is required"))]
    pub refresh_token: String,
}

/// Request body for `POST /api/v1/contact/auth/set-password`.
///
/// Redeems the emailed magic link (`{contact_id}.{secret}` shape,
/// stored in `portal_setup_tokens`). Same shape the pre-pivot portal
/// used; the payload is unchanged so the token minted by
/// `ContactService::grant_portal_access` in prompt 003 redeems here
/// without a wire-shape hop.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactSetPasswordRequest {
    #[validate(length(min = 1, message = "token is required"))]
    pub token: String,
    #[validate(length(min = 1, message = "password is required"))]
    pub password: String,
}

/// Request body for `POST /api/v1/contact/auth/forgot-password`.
/// Always returns 204 whether the (slug, email) pair matches or not
/// (enumeration-resistant).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactForgotPasswordRequest {
    #[validate(length(min = 1, max = 64, message = "portal slug is required"))]
    pub slug: String,
    #[validate(email)]
    pub email: String,
}

/// Request body for `POST /api/v1/contact/auth/reset-password`.
/// Redeems the emailed reset link. Same `{contact_id}.{secret}` shape
/// as setup-password.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactResetPasswordRequest {
    #[validate(length(min = 1, message = "token is required"))]
    pub token: String,
    #[validate(length(min = 1, message = "password is required"))]
    pub password: String,
}

/// Response body for `GET /api/v1/contact/portal/{slug}/host`. Public
/// endpoint used by the SPA to render branding + a "This portal is
/// not available" splash for suspended tenants (mirrors the pre-pivot
/// PortalHostHint shape, MAPPS-559).
#[derive(Debug, Clone, Serialize)]
pub struct ContactPortalHostHint {
    pub company_name: String,
    pub portal_slug: String,
    pub tenant_display_name: String,
    /// Raw `tenants.status` value (`active | suspended | cancelled`).
    /// SPA gates the login form on `status == "active"` and renders
    /// a suspended splash otherwise.
    pub tenant_status: String,
}
