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

/// `POST /api/v1/portal/auth/login` request body. `tenant_slug` is
/// required because `contacts.email` is only unique within a tenant.
/// A portal hosted at e.g. `portal.acme.example.com` should supply the
/// slug from the subdomain client-side; we don't strip it from the
/// Host header here because the host-to-tenant mapping is deployment
/// specific.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalLoginRequest {
    #[validate(length(min = 1, max = 100, message = "tenant_slug is required"))]
    pub tenant_slug: String,
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
