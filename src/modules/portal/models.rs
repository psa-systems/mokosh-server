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

/// Request body for `PATCH /api/v1/portal/auth/me`. First / last name
/// only for now; email and phone stay under agent-side ownership.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalUpdateMeRequest {
    #[validate(length(min = 1, max = 100, message = "First name is required (1-100 chars)"))]
    pub first_name: String,
    #[validate(length(min = 1, max = 100, message = "Last name is required (1-100 chars)"))]
    pub last_name: String,
}

/// Response body for `GET /api/v1/portal/auth/me`. Wraps the JWT-decoded
/// [`CurrentContact`] with account-state fields the SPA needs to render
/// the Settings page (currently MFA status) without a second round-trip.
/// Kept as a separate DTO so [`CurrentContact`] can stay the pure
/// JWT-claims snapshot everywhere else it is threaded.
#[derive(Debug, Clone, Serialize)]
pub struct CurrentContactMe {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub company_id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    /// `contacts.portal_mfa_enabled`. Drives the "Set up two-factor
    /// auth" vs "Two-factor auth is on" affordance on Settings and
    /// lets the login SPA decide (later) whether to short-circuit the
    /// MFA prompt entirely.
    pub mfa_enabled: bool,
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
    /// Wire-shape back-compat vestige: no shipped SPA fills this. Every
    /// portal deploy is host-derived; the SPA always sends an empty
    /// slug + `skip_serializing_if` drops the field. Kept so a hand-
    /// crafted client posting a body slug on a non-portal host still
    /// authenticates (the `portal_host_resolution.rs` integration
    /// tests cover the shim).
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

/// `POST /api/v1/portal/auth/forgot-password` request body. `email` is
/// the only credential-adjacent field; the tenant is resolved from
/// the request Host on every deploy. `tenant_slug` is a wire-shape
/// back-compat vestige (see `PortalLoginRequest` for the full story);
/// the SPA always sends it empty.
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

/// PMS-729 phase 2 H4: `POST /api/v1/portal/auth/me/mfa/setup`
/// request body. Post-code-review finding #3: setup + enable BOTH
/// require the caller's current password so a stolen access token
/// cannot enroll attacker-controlled MFA and lock the legitimate
/// user out. Same re-auth posture the change-password route uses.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalMfaSetupRequest {
    #[validate(length(min = 1, message = "Password is required"))]
    pub current_password: String,
}

/// PMS-729 phase 2 H4: `POST /api/v1/portal/auth/me/mfa/enable`
/// request body. The customer types the 6-8 digit code their
/// authenticator app shows; on success the server flips
/// `portal_mfa_enabled = TRUE`. Post-code-review finding #3: also
/// re-verifies the current password so a stolen access token cannot
/// finish an enrollment the attacker started.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalMfaEnableRequest {
    #[validate(length(min = 6, max = 8, message = "Code must be 6-8 digits"))]
    pub code: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub current_password: String,
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
    /// PMS-729 finalize: not-before, matches agent posture (MAPPS-334).
    /// Same second as `iat`; the leeway on the decode side absorbs
    /// clock skew. Defaulted for tokens minted before this claim was
    /// added so a rolling access-token TTL flushes cleanly.
    #[serde(default)]
    pub nbf: i64,
    /// PMS-729 finalize: token issuer (MAPPS-334 parity). Mint side
    /// always stamps `MOKOSH_JWT_ISSUER`; the decode side does not
    /// pin the value yet (see `decode_token` doc) so the strict
    /// flip is a no-op after the migration window rotates every
    /// live token.
    #[serde(default)]
    pub iss: String,
    /// PMS-729 finalize: intended audience (MAPPS-334 parity). Same
    /// migration posture as `iss`: minted now, validated later.
    #[serde(default)]
    pub aud: String,
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

// PMS-729 phase 2 §7 slice A / I17: portal dashboard payload -----------------

/// One row on the "Open tickets by priority" card. Includes the
/// priority's own display metadata (name, color, sort_order) so the SPA
/// can render an ordered list of chips without a second round-trip;
/// zero-count priorities are emitted so the axis stays stable as the
/// counts move over the day. Only OPEN tickets (`status.is_closed = false`)
/// contribute to `count`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DashboardTicketPriorityBucket {
    pub id: Uuid,
    pub name: String,
    pub color: String,
    pub sort_order: i32,
    pub count: i64,
}

/// The single "Next invoice due" card. Returns the earliest-due unpaid
/// invoice for the contact's company, or `None` when there is nothing
/// outstanding.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DashboardNextInvoiceDue {
    pub id: Uuid,
    pub invoice_number: String,
    pub total: rust_decimal::Decimal,
    pub balance_due: rust_decimal::Decimal,
    pub due_date: chrono::NaiveDate,
    pub currency: String,
}

/// One row on the "Recent activity" card. `kind` is a stable
/// machine-readable tag (`"ticket"`, `"invoice"`, `"quote"`) so the SPA
/// picks the right icon + link target without parsing the subject line;
/// `entity_id` is what the SPA appends to the entity's list URL for the
/// detail-view deep link.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DashboardRecentActivity {
    pub kind: String,
    pub entity_id: Uuid,
    pub label: String,
    pub summary: String,
    pub at: DateTime<Utc>,
}

/// `GET /portal/dashboard` response body. D17 from the plan doc pins
/// four cards for phase 2 (open tickets by priority, next invoice due,
/// open quotes awaiting decision, recent activity); this DTO is the
/// wire shape for all four. No pagination: the numbers are aggregate
/// summaries and the activity feed caps at the last ten events.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalDashboardResponse {
    pub tickets_by_priority: Vec<DashboardTicketPriorityBucket>,
    pub next_invoice_due: Option<DashboardNextInvoiceDue>,
    pub open_quotes_awaiting_decision: i64,
    pub recent_activity: Vec<DashboardRecentActivity>,
}

// PMS-729 phase 2 §7 slice A / I10: SLA visibility on portal ticket ---------

/// A computed SLA-status label with the same three states the agent
/// side uses (`on_track`, `warning`, `breached`), plus `not_applicable`
/// for a closed ticket or one that never had an SLA policy applied.
/// Serialised as snake_case so the wire matches the agent's
/// `mokosh_types::SlaStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalSlaStatus {
    OnTrack,
    Warning,
    Breached,
    NotApplicable,
}

/// `GET /portal/tickets/{id}/sla` response. Surfaces both SLA legs a
/// customer cares about (first-response and resolution) with the
/// due date and, when reached, the actual event timestamp, so the SPA
/// can render "target vs actual" side by side. `closed_at` is included
/// because it collapses both status fields to `not_applicable`.
///
/// Missing values (a ticket with no SLA policy) come back as `null` so
/// the SPA can hide those rows rather than render a spurious "no
/// target" placeholder.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalTicketSlaResponse {
    pub sla_due_date: Option<DateTime<Utc>>,
    pub first_response_due: Option<DateTime<Utc>>,
    pub first_response_at: Option<DateTime<Utc>>,
    pub resolution_due: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub status: PortalSlaStatus,
    /// The current ticket status name ("Open", "In Progress",
    /// "Resolved"...). Handy for the customer to see alongside the
    /// SLA metric without a second fetch.
    pub status_name: String,
}

// PMS-729 phase 2 §7 slice A / I11: payment history on invoice detail -------

/// One `payments` row as the portal wants to see it. The internal-
/// note field (`payments.notes`) is deliberately dropped: agents use
/// it to jot billing context ("bounced, retry Friday") that the
/// customer should not see. `gateway_response` is also omitted (it
/// carries raw Stripe / Auth.net payloads).
///
/// `reference_number` is included because on a check / wire /
/// off-portal payment it is the customer's own reference and they
/// often need to reconcile against their own ledger.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalInvoicePayment {
    pub id: Uuid,
    pub payment_date: chrono::NaiveDate,
    pub amount: rust_decimal::Decimal,
    pub payment_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_number: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// `GET /portal/invoices/{id}/payments` response body. Paginated by
/// convention; the current shape returns the full list (payments per
/// invoice are bounded by human behaviour, so a full list rarely
/// exceeds a page). Uses a wrapping object so future pagination
/// additions are non-breaking.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalInvoicePaymentsResponse {
    pub payments: Vec<PortalInvoicePayment>,
    pub total: i64,
}

// PMS-729 phase 2 §7 slice A / I14: portal search --------------------------

/// One matched row across every portal-searchable entity kind. Shape
/// matches the agent-side `SearchHit` so the SPA's grouped dropdown
/// can share the same primitive without a translation layer.
///
/// - `id` is the entity's primary key. The SPA composes the detail
///   URL per group (`/portal/tickets/<id>`, `/portal/invoices/<id>`).
/// - `label` is the primary line ("[T-1234] Server down", "INV-9002",
///   "How to reset your password").
/// - `secondary` is the small grey line beneath (status, due date,
///   article summary snippet) or `None` when the hit does not carry
///   secondary context.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalSearchHit {
    pub id: Uuid,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary: Option<String>,
}

/// Grouped response for `GET /portal/search`. Four sections in D18's
/// order (tickets, invoices, quotes, kb) so the SPA renders them
/// consistently. `counts` reports the true match count per section
/// (uncapped) so the SPA can render a "5+ tickets" affordance when
/// the top-5 preview clips the set.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PortalSearchResponse {
    pub tickets: Vec<PortalSearchHit>,
    pub invoices: Vec<PortalSearchHit>,
    pub quotes: Vec<PortalSearchHit>,
    pub kb_articles: Vec<PortalSearchHit>,
    pub counts: PortalSearchCounts,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PortalSearchCounts {
    pub tickets: i64,
    pub invoices: i64,
    pub quotes: i64,
    pub kb_articles: i64,
}

// Portal notification-preferences -------------------------------------------

/// One event_type the caller's tenant has an active rule for. `channels`
/// is the union of channels those rules fire on (`email`, `in_app`,
/// ...) so the SPA can render "You'll receive X via email + in-app"
/// alongside the on/off toggle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalNotificationEventOption {
    pub event_type: String,
    pub channels: Vec<String>,
}

/// One preference row from `contact_notification_preferences`. `is_enabled
/// = FALSE` suppresses the whole event; `channel_types` non-empty
/// restricts to specific channels when enabled.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortalNotificationPreference {
    pub event_type: String,
    pub is_enabled: bool,
    #[serde(default)]
    pub channel_types: Vec<String>,
}

/// `GET /portal/auth/me/notification-preferences` response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalNotificationPreferencesResponse {
    pub available: Vec<PortalNotificationEventOption>,
    pub preferences: Vec<PortalNotificationPreference>,
}

// PMS-729 phase 2 §7 slice B / I12: portal notifications inbox -------------

/// One in-app notification a contact can see in their portal inbox.
/// Payload is a stable projection over the shared `notifications` table:
/// subject + body (rendered per template), `read_at`, `created_at`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalNotification {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Joined from the row's `template_id` on read so the SPA can render
    /// a section-level deep-link (`ticket.note_added` -> Tickets,
    /// `sla.at_risk` -> Tickets, `invoice.due` -> Invoices, ...). Empty
    /// when the row has no template (legacy manual sends) or the
    /// template was deleted after the row landed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Kind of entity this notification is about (`ticket`, `invoice`,
    /// `quote`, ...). Written by the dispatcher when the render
    /// context carried an `entity_type` string. Empty for
    /// auth/system events with no single entity target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    /// Id of the entity this notification is about. Paired with
    /// `entity_type` so the SPA can construct a per-entity deep-link
    /// (e.g. `PortalTicketDetail { id: entity_id }`) instead of a
    /// section-level one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<Uuid>,
}

/// `GET /portal/notifications` response body. Carries the newest
/// `per_page` rows for the requested `page` (defaults 1 / 20), the
/// `unread_count` so the SPA can render the top-bar badge without
/// walking the row list, and a `total` so the notifications page can
/// render pagination controls. The bell menu keeps calling without
/// query params and gets the first page of 20; the dedicated
/// `/portal/notifications` page paginates.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalNotificationsResponse {
    pub notifications: Vec<PortalNotification>,
    pub unread_count: i64,
    /// Total number of in-app notifications for the caller across
    /// every page. Feeds pagination footer + "N more" affordance.
    #[serde(default)]
    pub total: i64,
}

// PMS-729 phase 2 §7 slice C: assets / contracts / time / projects --------

/// One asset as `GET /portal/assets` returns it. Internal `notes`
/// (agent scratch), `custom_fields`, RMM integration ids, and
/// `internal_notes` are dropped so agent-only context never leaks to
/// the customer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalAsset {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_tag: Option<String>,
    pub name: String,
    pub asset_type: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warranty_expiry: Option<chrono::NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_of_life: Option<chrono::NaiveDate>,
}

/// One contract as the portal list surface returns it. `internal_notes`
/// and `custom_fields` are dropped; SLA policy id / hour balance /
/// billing amount are all customer-facing and stay.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalContract {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_number: Option<String>,
    pub name: String,
    pub contract_type: String,
    pub status: String,
    pub start_date: chrono::NaiveDate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<chrono::NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_cycle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_amount: Option<rust_decimal::Decimal>,
}

/// One time entry as the portal returns it. Internal notes, hourly
/// rate, total amount, and approval reasons are dropped so agent
/// scratch context never reaches the customer. `duration_minutes`
/// stays because that is what the customer is verifying.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalTimeEntry {
    pub id: Uuid,
    pub date: chrono::NaiveDate,
    pub duration_minutes: i32,
    pub work_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub billing_status: String,
    pub approval_status: String,
    pub is_billable: bool,
}

/// One project as the portal list / detail returns it. Milestones
/// (via `PortalProjectPhase`) travel with the detail response only.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalProject {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_number: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date: Option<chrono::NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_end_date: Option<chrono::NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_end_date: Option<chrono::NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_hours: Option<rust_decimal::Decimal>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalProjectPhase {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: String,
    pub sort_order: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date: Option<chrono::NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<chrono::NaiveDate>,
}

/// Detail response for `GET /portal/projects/{id}`. Bundles the
/// project with its phase list so the SPA can render both without a
/// second fetch.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalProjectDetail {
    #[serde(flatten)]
    pub project: PortalProject,
    pub phases: Vec<PortalProjectPhase>,
}

// PMS-729 phase 2 §7 slice D / I13: multi-contact company view -------------

/// One sibling portal contact as `GET /portal/company/contacts` returns
/// them. Deliberately narrow: name + email + a boolean flag telling the
/// SPA which row is the caller. No phone, no title, no notes, no
/// activity - other people in the same company do not need those on a
/// portal roster.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalCompanyContact {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    /// `true` for the currently-authenticated contact. Lets the SPA
    /// highlight "this is you" and hide the "invite" affordance next
    /// to the caller's own row.
    pub is_you: bool,
}

/// PMS-729 follow-up: `POST /portal/company/contacts` body. Portal-side
/// invite-a-colleague. Caller identity + tenant + company come from the
/// verified JWT; the body carries only what the new contact IS
/// (name + email), never the tenant / company / role.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PortalInviteColleagueRequest {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

/// Response for `POST /portal/company/contacts`. Only the id is echoed;
/// the setup token goes out over email so the wire never carries the
/// credential a colleague uses to sign in.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalInviteColleagueResponse {
    pub id: Uuid,
}

// PMS-729 phase 2 §7 slice D / I7: approvals ------------------------------

/// One approval assigned to the caller. Mirrors the customer-visible
/// subset of `ticket_approvals`: the entity kind + id, a title, the
/// asking notes, requested_at, and the current status. Internal
/// requester id and role approver context are dropped.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalApproval {
    pub id: Uuid,
    pub target: String,
    pub entity_id: Uuid,
    /// A short label the SPA renders in the list ("Ticket #T-1234:
    /// Server down"). Cheap to derive server-side by joining tickets
    /// (the phase-1 target); other polymorphic targets fall back to
    /// the raw entity id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
}

/// `POST /portal/approvals/{id}/decide` request body. `decision` is
/// the discriminant; `decision_notes` is optional but encouraged.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PortalApprovalDecisionRequest {
    pub decision: String,
    #[serde(default)]
    pub decision_notes: Option<String>,
}

// PMS-729 phase 2 §7 slice D / I15: data export ---------------------------

/// One export job as `POST /portal/export` or `GET /portal/export/{id}`
/// returns it. `signed_url` is populated only after the worker finishes
/// (`status = 'ready'`) and blanks out again once `expires_at` passes
/// (the worker or the polling route also updates `status = 'expired'`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalExportJob {
    pub id: Uuid,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Post-code-review finding #7 follow-up: TRUE when any per-section
    /// fetch hit its cap and the bundle is incomplete. Always emitted
    /// (`skip_serializing_if` omitted deliberately) so the SPA can rely
    /// on the field's presence rather than treating the missing case as
    /// "unknown".
    #[serde(default)]
    pub bundle_truncated: bool,
    /// Per-section row counts observed at bundle time (`{tickets, notes,
    /// invoices, quotes}`). `None` until the worker generates the
    /// bundle; kept `None` on failed / never-run rows so the SPA does
    /// not render a zero-count table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_section_totals: Option<serde_json::Value>,
}

// PMS-729 phase 2 §7 slice D / I18: delegation ----------------------------

/// One delegation as the portal returns it. Scope is echoed back
/// verbatim so the SPA renders the checkbox row per key it knows.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalDelegation {
    pub id: Uuid,
    pub delegatee_contact_id: Uuid,
    pub delegatee_name: String,
    pub delegatee_email: String,
    pub scope: serde_json::Value,
    pub granted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Inverse of [`PortalDelegation`]: one delegation another colleague
/// has granted TO the caller. Same scope shape; identifies the
/// granting colleague so the SPA can render a "Access shared by ..."
/// panel next to the outgoing-grants list.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortalIncomingDelegation {
    pub id: Uuid,
    pub delegator_contact_id: Uuid,
    pub delegator_name: String,
    pub delegator_email: String,
    pub scope: serde_json::Value,
    pub granted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// `POST /portal/company/delegations` request body. `scope` is an
/// opaque JSON object; the server does not validate its shape today
/// (the SPA controls the key set).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PortalDelegationGrantRequest {
    pub delegatee_contact_id: Uuid,
    #[serde(default)]
    pub scope: serde_json::Value,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}
