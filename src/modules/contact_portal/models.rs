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
    /// mokosh-contact-login option-1 first-login gate: when a
    /// magic-link redeem resolves to a contact whose
    /// `portal_password_hash` is NULL, the server refuses to mint the
    /// session and returns this URL instead. The SPA MUST navigate to
    /// it so the recipient sets a password before landing on
    /// `/dashboard`. Every future login for that contact then has both
    /// paths (magic-link OR password) available. `None` on the happy
    /// path (contact already has a password set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_setup_url: Option<String>,
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
    /// MAPPS-617: resolved brand for this contact's tenant + Company
    /// so the SPA can paint the in-app surfaces (sidebar, dashboard,
    /// ticket detail) without an extra `/host` round-trip after
    /// sign-in. On the login mfa-required path this field is omitted
    /// (no contact object is returned then, so the SPA falls back to
    /// the branding it already fetched via `/portal/{id}/host` at
    /// step 2). Legacy responses that pre-date this field deserialize
    /// to `EffectiveBranding::default()` (all `None`).
    #[serde(default)]
    pub effective_branding: mokosh_types::tenants::EffectiveBranding,
}

/// MAPPS-618 (mokosh-branding prompt 002): response body for
/// `GET /api/v1/contact/companies/self/branding`. Powers the
/// contact-plane branding editor's "Inherits from MSP default: X"
/// hints: the SPA holds the raw tenant + Company sides so a per-field
/// reset (`Match MSP default`) can show what the fall-back looks
/// like without recomputing the merge client-side.
#[derive(Debug, Clone, Serialize)]
pub struct ContactOwnCompanyBranding {
    pub tenant: mokosh_types::tenants::TenantBranding,
    pub company: mokosh_types::contacts::CompanyBranding,
    pub effective: mokosh_types::tenants::EffectiveBranding,
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
/// endpoint. Post MAPPS-637 the shape is a single `Option`: `auto`
/// is populated on the single-match happy path (session already
/// minted, or MFA/set-password gated), and `None` when the token
/// is invalid / expired / would have resolved to more than one
/// portal contact (aggregate-by-email retired; multi-match folds
/// to the same invalid shape). The legacy `candidates` field is
/// kept for one release cycle for wire compatibility with an
/// out-of-date client; it is always `None`.
#[derive(Debug, Clone, Serialize)]
pub struct LoginLinkRedeemOutcome {
    pub auto: Option<ContactLoginResponse>,
    /// MAPPS-637: always `None`. Field retained for one release
    /// cycle so a client on the older wire still deserialises the
    /// response body without a schema mismatch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<serde_json::Value>,
}

/// mokosh-contact-login prompt 010: request body for
/// `POST /api/v1/contact/auth/login-link/redeem`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactRedeemLoginLinkRequest {
    #[validate(length(min = 1, message = "token is required"))]
    pub token: String,
}

// MAPPS-637: `LoginLinkCandidates`, `LoginLinkCandidate`,
// `ContactSelectLoginCandidateRequest`, and `ContactLoginSelectClaims`
// were the aggregate-by-email machinery. All retired with the
// `/login-link/select` route in the same ticket; nothing on the
// wire reads or writes them any more.

/// PMS-935: response body for `GET /api/v1/contact/dashboard/summary`.
/// Every counter is scoped to the signed-in contact's Company; the
/// `recent_activity` feed is capped at 10 items and sorted DESC on
/// `occurred_at`. Reads the same source-of-truth tables the staff
/// workspace uses so there is no denormalisation to drift.
#[derive(Debug, Clone, Serialize)]
pub struct ContactDashboardSummary {
    pub open_tickets: i64,
    pub unpaid_invoices: i64,
    pub active_quotes: i64,
    pub active_contracts: i64,
    pub recent_activity: Vec<ActivityItem>,
}

/// PMS-935: one row of `ContactDashboardSummary.recent_activity`.
/// Distinct from the internal audit-log row shape (which carries
/// actor / entity / diff): this is a customer-facing snippet the
/// SPA renders in a widget alongside the tile grid.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityItem {
    /// Discriminator so the SPA can render an icon / route: one of
    /// `"ticket" | "invoice" | "quote" | "contract"`.
    pub kind: String,
    pub id: Uuid,
    /// Human-short label (e.g. the ticket title or invoice number).
    pub summary: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

/// PMS-935: request body for `PUT /api/v1/contact/auth/me`. Every
/// field is `Option`: a `None` (or an unsupplied JSON key) is treated
/// as "leave unchanged" so the SPA can PATCH a single attribute
/// without needing to round-trip the full contact row. Email is NOT
/// accepted here - the staff CRM owns portal identity, so contacts
/// cannot self-serve their own email address change via the portal.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ContactSelfUpdateRequest {
    #[validate(length(min = 1, max = 100))]
    pub first_name: Option<String>,
    #[validate(length(min = 1, max = 100))]
    pub last_name: Option<String>,
    #[validate(length(max = 32))]
    pub phone: Option<String>,
    #[validate(length(max = 32))]
    pub mobile: Option<String>,
    pub timezone: Option<String>,
    pub notification_preferences: Option<serde_json::Value>,
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
    /// MAPPS-617: fully resolved brand for the (tenant, Company) tuple
    /// so the SPA paints logo + colors + background + wordmark on the
    /// step-2 login without a second round-trip. Every field is
    /// `Option<String>`; both sides falling through leaves `None` and
    /// the SPA supplies the coded default.
    pub effective_branding: mokosh_types::tenants::EffectiveBranding,
}
