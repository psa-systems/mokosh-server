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
    pub fn full_name(&self) -> String {
        format!("{} {}", self.first_name, self.last_name)
    }
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
