//! Portal-side DTOs and JWT claim shapes.
//!
//! The portal-side `CurrentContact` carries `tenant_id` *and* `company_id`
//! so handlers can scope queries to "this contact's company" without
//! re-reading the contacts row.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Per-request portal auth state, mirrors the agent-side `AuthState`.
#[derive(Debug, Clone, Default)]
pub struct PortalAuthState {
    pub contact: Option<CurrentContact>,
    /// PMS-729 phase 2 H6: session id (= id of the refresh token that
    /// minted the caller's access token, from the JWT `sid` claim).
    /// `None` for an anonymous request; carried alongside the contact
    /// so `/portal/auth/me/sessions` can mark the caller's own
    /// session as `current` and `DELETE /me/sessions/{id}` can refuse
    /// self-revoke.
    pub sid: Option<Uuid>,
}

impl PortalAuthState {
    pub fn authenticated(contact: CurrentContact, sid: Uuid) -> Self {
        Self {
            contact: Some(contact),
            sid: Some(sid),
        }
    }
}

/// Authenticated portal contact. The handler-facing snapshot of the
/// `contacts` row + the JWT claims that scope queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentContact {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub company_id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

impl CurrentContact {
    /// PMS-479: wrap the verified `tenant_id` claim into a
    /// `TenantId` so portal handlers do not have to spell out
    /// `crate::modules::auth::TenantId::from_trusted(contact.tenant_id)`
    /// at every service call. The seam is the same: a portal session
    /// is a verified JWT, the wrapped UUID is a server-side trust
    /// boundary, and `from_trusted` is the sanctioned bridge - this
    /// helper just makes the call site one term instead of three.
    #[cfg(feature = "server")]
    pub fn tenant(&self) -> crate::modules::auth::TenantId {
        crate::modules::auth::TenantId::from_trusted(self.tenant_id)
    }
}

/// `POST /api/v1/portal/auth/login` request body.
///
/// `tenant_slug` was mandatory before PMS-729; it is now optional so the
/// login handler can resolve the tenant from the Host header when the
/// portal is served under `{slug}.client.<apex>`. The resolution policy
/// (host-only / body-only / both-must-match / neither-fails-closed) lives
/// on [`super::host_tenant::resolve_slug`]. Legacy `?tenant=X` links that
/// still fill this field continue to authenticate.
#[derive(Debug, Clone, Deserialize, Validate, Default)]
pub struct PortalLoginRequest {
    /// Deprecated for new clients; kept for the legacy `?tenant=` path.
    /// Missing OR present-and-matching-host both authenticate; a body
    /// slug that disagrees with the host slug fails closed with the
    /// wrong-password envelope (PMS-729 AC).
    #[serde(default)]
    #[validate(length(max = 100, message = "tenant_slug too long"))]
    pub tenant_slug: Option<String>,
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    /// PMS-729 phase 2 H8: Cloudflare Turnstile response token. Only
    /// required after the source IP has crossed the failure threshold;
    /// otherwise ignored. The SPA gets the site key via
    /// `window.__MOKOSH_CONFIG__.turnstile_site_key` (feature off = key
    /// absent = widget never renders). Empty string treated as
    /// "not supplied".
    #[serde(default)]
    pub captcha_token: Option<String>,
    /// PMS-729 phase 2 H4: 6-8 digit TOTP code. Required on the second
    /// login attempt when the first came back with `mfa_required: true`
    /// AND the contact has MFA enabled. Ignored for contacts without
    /// MFA. Same shape as agent's `LoginRequest.mfa_code`.
    #[serde(default)]
    pub mfa_code: Option<String>,
    /// PMS-729 phase 2 H4: single-use recovery code. When supplied
    /// alongside a valid password + a MFA-enabled contact, bypasses
    /// `mfa_code`; the matched hash is removed from
    /// `contacts.portal_mfa_recovery_codes_hashes` on success. Same
    /// shape as agent's `LoginRequest.recovery_code`.
    #[serde(default)]
    pub recovery_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PortalLoginResponse {
    /// Empty when `mfa_required = true` (the caller must re-POST with
    /// `mfa_code` or `recovery_code` to actually get a token).
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    /// PMS-729 phase 2 H1+H2: opaque refresh token (returned only at
    /// login and refresh time; NEVER stored anywhere but the SPA's
    /// non-cookie session storage). Present the token to
    /// `POST /portal/auth/refresh` before the access token expires to
    /// rotate both tokens and keep the session alive; present it to
    /// `POST /portal/auth/logout` to revoke the entire rotation chain.
    ///
    /// Format: `{token_id}.{secret}`. Only the Argon2id hash of `secret`
    /// is stored server-side; the plaintext value is unrecoverable.
    ///
    /// Empty when `mfa_required = true`.
    pub refresh_token: String,
    /// Absolute expiry of `refresh_token`. The SPA uses this to schedule
    /// its background refresh call before the token expires.
    pub refresh_expires_at: DateTime<Utc>,
    /// PMS-729 phase 2 H4: contact identity. Omitted (None) while
    /// `mfa_required` is true so no profile data leaks before the
    /// second factor is satisfied. Same posture as agent's
    /// `LoginResponse.user`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<CurrentContact>,
    /// PMS-729 phase 2 H4: `true` iff the contact has MFA enabled and
    /// no valid `mfa_code` / `recovery_code` was supplied. The SPA
    /// picks this up, collects the code, and re-POSTs the same login
    /// with the additional field.
    #[serde(default)]
    pub mfa_required: bool,
}

/// PMS-729 phase 2 H2: `POST /api/v1/portal/auth/refresh` request body.
/// The refresh token is presented in the body (NOT the Authorization
/// header) because it is not a Bearer credential in the OAuth sense.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalRefreshRequest {
    #[validate(length(min = 1, message = "refresh_token is required"))]
    pub refresh_token: String,
}

/// PMS-729 phase 2 H2: `POST /api/v1/portal/auth/refresh` response body.
/// Rotates BOTH the access token and the refresh token: the caller must
/// replace both. The old refresh token is revoked as a side effect of
/// the rotation; presenting it again fails closed (and is treated as a
/// replay signal that revokes the entire rotation chain).
#[derive(Debug, Clone, Serialize)]
pub struct PortalRefreshResponse {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_token: String,
    pub refresh_expires_at: DateTime<Utc>,
}

/// PMS-729 phase 2 H3: `POST /api/v1/portal/auth/forgot-password`
/// request body. `email` is the only credential-adjacent field; the
/// tenant is resolved from the request Host (PMS-729) or from an
/// optional `tenant_slug` fallback for the legacy body-slug path.
///
/// The endpoint always returns 204 regardless of whether the email
/// matched any known contact: the response shape MUST NOT leak whether
/// an address is on the portal (matches the wrong-password
/// enumeration-resistance posture on `/portal/auth/login`).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalForgotPasswordRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    /// Legacy body-slug fallback; ignored when the Host resolves to an
    /// active tenant. Same shape as [`PortalLoginRequest::tenant_slug`].
    #[serde(default)]
    #[validate(length(max = 100, message = "tenant_slug too long"))]
    pub tenant_slug: Option<String>,
}

/// PMS-729 phase 2 H3: `POST /api/v1/portal/auth/reset-password`
/// request body. `token` is the emailed `{token_id}.{secret}` pair;
/// `password` is the new credential and is validated through the
/// shared `utils::password_policy` module (H5).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalResetPasswordRequest {
    #[validate(length(min = 1, message = "token is required"))]
    pub token: String,
    // Length + strength check lives in the service layer via
    // `utils::password_policy` (PMS-729 phase 2 H5). The validator
    // layer only enforces "not empty" so the strength module is the
    // single source of truth for the password rules.
    #[validate(length(min = 1, message = "password is required"))]
    pub password: String,
}

/// PMS-729 phase 2 H3: `PUT /api/v1/portal/auth/me/password` request
/// body. The `RequirePortalAuth` extractor identifies the contact from
/// the access token, so this body only carries `current_password` (for
/// re-auth) and `new_password`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalChangePasswordRequest {
    #[validate(length(min = 1, message = "current_password is required"))]
    pub current_password: String,
    #[validate(length(min = 1, message = "new_password is required"))]
    pub new_password: String,
}

/// PMS-729 phase 2 H1: `POST /api/v1/portal/auth/logout` request body.
/// Revokes the presented refresh token and every other refresh token
/// currently live in the same rotation chain, so a stolen access token
/// cannot be refreshed after the customer signs out on their end. The
/// access token itself is not stored server-side and expires on its
/// own; logout is defence-in-depth on top of that.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalLogoutRequest {
    #[validate(length(min = 1, message = "refresh_token is required"))]
    pub refresh_token: String,
}

/// PMS-729 phase 2 H4: `POST /api/v1/portal/auth/me/mfa/setup`
/// response. Called once (before enrollment); returns a fresh TOTP
/// secret + provisioning URI the SPA displays as a QR code. The
/// secret is persisted immediately on `contacts.portal_mfa_secret`
/// but `portal_mfa_enabled` stays FALSE until `/enable` confirms
/// ownership. Calling this again before `/enable` REPLACES the
/// stored secret (fine; the customer never got past setup).
#[derive(Debug, Clone, Serialize)]
pub struct PortalMfaSetupResponse {
    /// Base32-encoded secret. Displayed on the SPA for manual entry
    /// (users who cannot scan the QR code copy this into their
    /// authenticator app).
    pub secret: String,
    /// `otpauth://totp/...` URI suitable for QR-code encoding.
    pub provisioning_uri: String,
}

/// PMS-729 phase 2 H4: `POST /api/v1/portal/auth/me/mfa/enable`
/// request body. The customer types the 6-8 digit code their
/// authenticator app shows; on success the server flips
/// `portal_mfa_enabled = TRUE`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalMfaEnableRequest {
    #[validate(length(min = 6, max = 8, message = "Code must be 6-8 digits"))]
    pub code: String,
}

/// PMS-729 phase 2 H4: `POST /api/v1/portal/auth/me/mfa/enable`
/// response. Carries the freshly-minted recovery codes; the SPA
/// MUST prompt the customer to save them, because the server
/// stores only the Argon2id hashes and will never surface them
/// again.
#[derive(Debug, Clone, Serialize)]
pub struct PortalMfaEnableResponse {
    /// 10 single-use codes in `XXXXX-XXXXX` format. Each can be
    /// submitted as `PortalLoginRequest.recovery_code` exactly once.
    pub recovery_codes: Vec<String>,
}

/// PMS-729 phase 2 H4: `POST /api/v1/portal/auth/me/mfa/disable`
/// request body. Requires the current password AND a valid TOTP so a
/// stolen access token cannot disable the second factor silently.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalMfaDisableRequest {
    #[validate(length(min = 1, message = "current_password is required"))]
    pub current_password: String,
    #[validate(length(min = 6, max = 8, message = "Code must be 6-8 digits"))]
    pub code: String,
}

/// Customer-facing ticket creation. Intentionally narrower than the
/// agent-side `CreateTicketRequest`: a contact can describe the
/// problem and pick urgency, but everything else (assignment,
/// scheduling, contract/SLA picks, billing flags) is the agent's
/// call after triage. `company_id` and `contact_id` come from the
/// `RequirePortalAuth` extractor; the source is hard-coded to
/// `Portal`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreatePortalTicketRequest {
    #[validate(length(min = 1, max = 200, message = "Title is required (1-200 chars)"))]
    pub title: String,
    pub description: Option<String>,
    pub priority_id: Option<Uuid>,
    pub type_id: Option<Uuid>,
}

/// PMS-449: portal-side body for adding a comment to one of the
/// contact's own company's tickets. Intentionally narrower than the
/// agent-side `CreateNoteRequest`: a customer cannot choose
/// `note_type` (server forces `public`) or trigger an outbound email
/// (the agent path's `send_email` is not exposed here - the
/// notifications dispatcher fans out on its own rules).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreatePortalTicketNoteRequest {
    #[validate(length(min = 1, max = 10_000, message = "Comment is required (1-10000 chars)"))]
    pub content: String,
}

/// `POST /api/v1/portal/auth/setup-password` request body. The customer
/// lands here from the emailed `/portal/set-password?token=...` link
/// (PMS-136). `token` is the single-use setup token (`{contact_id}.{secret}`);
/// `password` is the credential they choose. On success the contact's
/// `portal_password_hash` is set and they can immediately sign in via
/// `/portal/auth/login`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalSetupPasswordRequest {
    #[validate(length(min = 1, message = "token is required"))]
    pub token: String,
    // Length + strength check lives in `PortalAuthService::setup_password`
    // via the shared `utils::password_policy` (PMS-729 phase 2 H5). The
    // validator layer only enforces "not empty" so the strength module
    // is the single source of truth for the password rules.
    #[validate(length(min = 1, message = "password is required"))]
    pub password: String,
}

/// PMS-729: an active tenant resolved from the request Host by
/// [`super::host_tenant::PortalHostConfig::extract_slug`] +
/// [`super::service::PortalAuthService::resolve_host_tenant`]. Carries
/// enough for the login policy check + the phase 2 §6 branding
/// response.
#[derive(Debug, Clone)]
pub struct ResolvedTenant {
    pub tenant_id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub branding: PortalBranding,
}

/// PMS-729 phase 2 §6: full MSP branding surface pulled from
/// `tenants.branding` JSONB. Every field is optional; empty branding
/// = the SPA falls back to the generic "Client Portal" look. Every
/// URL field is stored as a raw string so the SPA can point at any
/// CDN / data URI / same-origin asset (validation lives in the
/// branding-editor endpoint that MAPPS-420 will add; this read
/// contract accepts whatever the writer put on the row).
///
/// Color fields use the CSS custom-property model (D10, phase-2-plan
/// §6.3): the SPA sets `--brand-primary` etc. on `:root` from these
/// values and validates AA contrast at read time (D11). A missing
/// color leaves the design-token default in place.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortalBranding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// Optional dark-mode logo variant. When absent, the SPA renders
    /// `logo_url` regardless of theme (fine for a single-color mark;
    /// a full-color logo benefits from a dark variant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_url_dark: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon_url: Option<String>,
    /// CSS color for the primary brand accent (buttons, links). Any
    /// CSS color value the browser accepts (`#2563eb`, `rgb(...)`,
    /// `hsl(...)`). The SPA runs a contrast check against the light-
    /// mode surface tokens; a failing value falls back to the design
    /// token silently and logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    /// Optional dark-mode primary color. When absent, the SPA reuses
    /// `primary_color` under dark theme (browser handles the
    /// contrast check the same way).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_color_dark: Option<String>,
    /// Contact email the SPA shows in the "need help?" section of the
    /// portal footer + auth pages. Not validated as an email at the
    /// read layer (MAPPS-420 owns the write validation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_hours: Option<String>,
    /// Short MSP-owned footer text. Renders in the portal footer in
    /// place of the generic "Powered by Mokosh Platform" line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footer_text: Option<String>,
    /// Short one-liner above the login credentials block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_message: Option<String>,
}

impl PortalBranding {
    /// Parse a `tenants.branding` JSONB blob. A wholly-missing or
    /// malformed blob returns the empty default rather than erroring
    /// out - a stray typo in the branding editor must never break a
    /// login.
    pub fn from_jsonb(v: &serde_json::Value) -> Self {
        serde_json::from_value(v.clone()).unwrap_or_default()
    }
}

/// PMS-729: response body for `GET /api/v1/portal/host`. Returns the
/// active tenant's display name + full branding surface so the SPA
/// can paint MSP-owned chrome (logo, favicon, primary color, welcome
/// message, support contact) before a session exists. Fail-closed:
/// an unknown or malformed host returns `404 Not Found` with an empty
/// body so the endpoint cannot be used to enumerate live MSPs.
///
/// PMS-729 phase 2 §6: extended from `{name, logo_url}` to carry the
/// full branding shape via [`PortalBranding`] (flattened into the
/// response body so callers see a flat object, not `{name, branding:
/// {...}}`).
#[derive(Debug, Clone, Serialize)]
pub struct PortalHostHint {
    pub name: String,
    #[serde(flatten)]
    pub branding: PortalBranding,
}

/// JWT claim shape for portal access tokens. Kept separate from the
/// agent-side `JwtClaims` to avoid type drift if one side learns new
/// fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalJwtClaims {
    /// Subject = contact id.
    pub sub: Uuid,
    /// Tenant id.
    pub tid: Uuid,
    /// Company id (scopes most queries).
    pub cid: Uuid,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
    /// Constant `"portal_access"`. Distinguishes portal tokens from
    /// agent tokens minted by `AuthService`.
    pub typ: String,
    /// PMS-729 phase 2 H2: unique per-token JWT ID (RFC 7519 §4.1.7).
    /// Guarantees every minted access token has a distinct byte sequence
    /// even when two mints share the same second-granularity `iat`/`exp`,
    /// and gives a future revocation-store implementation a stable
    /// primary key.
    #[serde(default)]
    pub jti: Uuid,
    /// PMS-729 phase 2 H6: session id = id of the refresh token that
    /// minted this access token. Ties an access token to a specific
    /// row in `portal_refresh_tokens` so `GET /me/sessions` can mark
    /// the caller's own session as `is_current` and `DELETE
    /// /me/sessions/{id}` can no-op safely when the caller tries to
    /// delete their own session. Rotates on every `/refresh` (a new
    /// refresh token id => a new sid).
    #[serde(default)]
    pub sid: Uuid,
}

/// PMS-729 phase 2 H6: one row on `GET /portal/auth/me/sessions`.
/// Wraps a live `portal_refresh_tokens` row with just the fields a
/// customer needs to see + a `current` flag so the SPA can highlight
/// the session they're viewing from.
#[derive(Debug, Clone, Serialize)]
pub struct PortalSessionResponse {
    /// Refresh token id. Matches the `sid` claim on the access token
    /// that minted this row (per rotation, so this is the id of the
    /// LIVE refresh token in the chain, not any ancestor).
    pub id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// `true` when this session's rotation chain contains the sid
    /// claim off the caller's access token. Lets the SPA highlight
    /// "this browser" and hide the delete button for it (a customer
    /// signing themselves out uses `/portal/auth/logout`, not the
    /// per-session delete).
    pub current: bool,
}
