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
}

impl PortalAuthState {
    pub fn authenticated(contact: CurrentContact) -> Self {
        Self {
            contact: Some(contact),
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
}

#[derive(Debug, Clone, Serialize)]
pub struct PortalLoginResponse {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    pub contact: CurrentContact,
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
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

/// PMS-729: an active tenant resolved from the request Host by
/// [`super::host_tenant::PortalHostConfig::extract_slug`] +
/// [`super::service::PortalAuthService::resolve_host_tenant`]. Carries
/// just enough for the login policy check + the branding-hint response.
#[derive(Debug, Clone)]
pub struct ResolvedTenant {
    pub tenant_id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub logo_url: Option<String>,
}

/// PMS-729: response body for `GET /api/v1/portal/host`. Returns the
/// active tenant's display name + logo URL so the SPA login page can
/// paint MSP-owned branding above the credential fields before a
/// session exists. Fail-closed: an unknown or malformed host returns
/// `404 Not Found` with an empty body so the endpoint cannot be used to
/// enumerate live MSPs.
#[derive(Debug, Clone, Serialize)]
pub struct PortalHostHint {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
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
}
