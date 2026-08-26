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
///
/// mokosh-contact-login prompt 011 (PMS-928): the body now dual-accepts
/// `portal_id` (9-digit numeric, preferred) alongside `slug` (legacy
/// 16-char Crockford, kept for one release cycle so live invitation
/// emails from prompts 003-010 keep working). At least one of the two
/// must be present; if both are, `portal_id` wins.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactLoginRequest {
    /// Company's 9-digit numeric Portal ID. Preferred over `slug`.
    /// Optional to preserve the pre-prompt-011 wire shape for callers
    /// that still send only `slug`.
    #[serde(default)]
    pub portal_id: Option<i64>,
    /// Legacy Company `portal_slug`. Optional as of prompt 011; when
    /// omitted, `portal_id` must be present. Kept in place while the
    /// compat redirect drains the last portal_slug-shape invitation
    /// URLs.
    #[serde(default)]
    pub slug: Option<String>,
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

/// mokosh-contact-login prompt 010 (PMS-918): request body for
/// `POST /api/v1/contact/auth/login-link`. Slug-less: the finder
/// resolves the tenant from an optional `slug` (a Company's
/// `portal_slug`) the SPA passes when it has one in localStorage. If
/// absent, the request cannot pin down a tenant and the server drops
/// silently (still returns 204 so an attacker cannot use the shape as
/// an enumeration oracle).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactRequestLoginLinkRequest {
    #[validate(email)]
    pub email: String,
    /// Optional Company `portal_slug` the SPA remembers in
    /// localStorage from a prior sign-in. The server maps it to a
    /// tenant so the intent row lands under the right tenant and the
    /// eventual redeem step sees the matching contacts. Omitted on a
    /// fresh install.
    #[serde(default)]
    pub slug: Option<String>,
    /// mokosh-contact-login prompt 011 (PMS-928): optional Company
    /// `portal_id` (9-digit numeric). Preferred over `slug` when both
    /// are supplied. When present, the finder scopes the eventual
    /// redeem-time contact lookup to this Company so a duplicated
    /// email across two Companies inside the same MSP tenant auto-
    /// mints for the Portal ID's Company instead of showing the
    /// picker.
    #[serde(default)]
    pub portal_id: Option<i64>,
}

/// mokosh-contact-login prompt 010: response body of the redeem
/// endpoint. Exactly one of the two Options is populated on any
/// success:
/// - `auto` for the single-match / MFA-pending case: session is either
///   already minted (`mfa_required = false`) or gated on TOTP
///   (`mfa_required = true`).
/// - `candidates` for the multi-match case: the SPA renders a picker
///   and posts back to `/login-link/select` with the chosen
///   `contact_id` plus the `selection_token`.
#[derive(Debug, Clone, Serialize)]
pub struct LoginLinkRedeemOutcome {
    pub auto: Option<ContactLoginResponse>,
    pub candidates: Option<LoginLinkCandidates>,
}

/// mokosh-contact-login prompt 010: multi-Company picker payload
/// returned when a magic-link redeem resolves to two or more portal
/// contacts under the same email. The SPA renders one tile per row,
/// on click POSTs `{selection_token, contact_id}` to
/// `/login-link/select`. The selection token is a JWT carrying the
/// candidate contact-id set + an expiry so the caller cannot swap a
/// contact_id that was never in the list.
#[derive(Debug, Clone, Serialize)]
pub struct LoginLinkCandidates {
    pub selection_token: String,
    pub companies: Vec<LoginLinkCandidate>,
}

/// mokosh-contact-login prompt 010: one row of `LoginLinkCandidates`.
/// `contact_id` uniquely identifies the portal account (a single
/// email can back several contacts under different Companies inside
/// the same MSP tenant). `company_name` + `portal_slug` are pure
/// display fields for the picker tile.
#[derive(Debug, Clone, Serialize)]
pub struct LoginLinkCandidate {
    pub contact_id: Uuid,
    pub company_name: String,
    pub portal_slug: String,
}

/// mokosh-contact-login prompt 010: request body for
/// `POST /api/v1/contact/auth/login-link/redeem`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactRedeemLoginLinkRequest {
    #[validate(length(min = 1, message = "token is required"))]
    pub token: String,
}

/// mokosh-contact-login prompt 010: request body for
/// `POST /api/v1/contact/auth/login-link/select`. `contact_id` MUST
/// be one of the ids carried in the `selection_token`'s
/// `candidate_contact_ids` claim, otherwise the request 400s. This
/// prevents a caller from swapping the selection token to an
/// unrelated contact.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactSelectLoginCandidateRequest {
    #[validate(length(min = 1, message = "selection_token is required"))]
    pub selection_token: String,
    pub contact_id: Uuid,
    /// TOTP code, sent on the second attempt after a `mfa_required`
    /// response. Optional today (contact MFA is off by default;
    /// reserved for a follow-up ticket that adds the enrol flow).
    #[serde(default)]
    pub mfa_code: Option<String>,
}

/// mokosh-contact-login prompt 010: JWT claims for the short-lived
/// `contact_login_select` token. Encodes the intent id, the tenant,
/// and the candidate set so the select endpoint can verify the
/// caller-supplied `contact_id` is one of the ones that actually
/// matched at redeem time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactLoginSelectClaims {
    pub intent_id: Uuid,
    pub tid: Uuid,
    pub candidate_contact_ids: Vec<Uuid>,
    #[serde(rename = "typ")]
    pub token_type: String,
    pub iat: i64,
    pub exp: i64,
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
