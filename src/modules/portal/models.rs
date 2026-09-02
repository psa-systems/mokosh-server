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
    /// PMS-993: whether this contact is `company_id`'s billing contact, and so
    /// holds the billing role for this session. Read from the row on every
    /// request rather than minted into the JWT, so revoking the role takes
    /// effect on the next request instead of the next login (and so the
    /// PMS-195 claim-minimisation posture is unchanged).
    pub is_billing_contact: bool,
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

/// `POST /api/v1/portal/auth/forgot-password` request body (PMS-820).
/// `tenant_slug` is required for the same reason login requires it:
/// `contacts.email` is only unique within a tenant, and the portal must
/// resolve the identity inside its own tenant rather than against the
/// platform's `users` table.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PortalForgotPasswordRequest {
    #[validate(length(min = 1, max = 100, message = "tenant_slug is required"))]
    pub tenant_slug: String,
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
}

/// `POST /api/v1/portal/auth/reset-password` request body (PMS-820).
/// Deliberately the same `{contact_id}.{secret}` token plus password as
/// [`PortalSetupPasswordRequest`]: the portal has one contact-bound token
/// shape, so redeeming a self-service reset link and redeeming an
/// agent-minted setup link take the same body and answer with the same
/// statuses.
pub type PortalResetPasswordRequest = PortalSetupPasswordRequest;

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

/// What `portal_auth_middleware` needs from the `contacts` row on every
/// request, in one read.
///
/// The names are not minted into the JWT (PII minimisation, PMS-195), so the
/// middleware was already loading this row; MAPPS-532's revocation cutoff
/// rides along in the same query rather than adding a second round trip.
#[derive(Debug, Clone)]
pub struct PortalContactSnapshot {
    pub first_name: String,
    pub last_name: String,
    /// MAPPS-532: reject a token minted before this instant. `None` (the
    /// column's default, and every row that predates the migration) means the
    /// contact has never signed out, so nothing is revoked.
    pub tokens_valid_from: Option<DateTime<Utc>>,
    /// PMS-993: whether this contact is the billing contact of the company in
    /// the token's `cid` claim. Rides along in the same read for the same
    /// reason the cutoff does.
    pub is_billing_contact: bool,
}

impl PortalContactSnapshot {
    /// Whether a token issued at `token_iat` (seconds since the epoch) has
    /// been revoked by a sign-out.
    ///
    /// Strictly `<`, matching `AuthService::ensure_user_and_tenant_active`:
    /// `iat` has one-second resolution, so a contact who signs out and
    /// straight back in inside the same second must keep the token they just
    /// received.
    pub fn revokes(&self, token_iat: i64) -> bool {
        match self.tokens_valid_from {
            Some(cutoff) => token_iat < cutoff.timestamp(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(cutoff: Option<DateTime<Utc>>) -> PortalContactSnapshot {
        PortalContactSnapshot {
            first_name: "Portal".to_string(),
            last_name: "Contact".to_string(),
            tokens_valid_from: cutoff,
            is_billing_contact: false,
        }
    }

    /// MAPPS-532: a contact who has never signed out revokes nothing, so the
    /// column being NULL on every pre-migration row cannot lock anyone out.
    #[test]
    fn no_cutoff_revokes_nothing() {
        assert!(!snapshot(None).revokes(0));
        assert!(!snapshot(None).revokes(i64::MAX));
    }

    /// The boundary is the whole design. `iat` is stamped in whole seconds, so
    /// a contact who signs out and immediately back in gets a token whose
    /// `iat` equals the cutoff; treating that as revoked would sign them out
    /// of the session they just created.
    #[test]
    fn a_token_minted_in_the_same_second_as_the_sign_out_survives() {
        let cutoff = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let snap = snapshot(Some(cutoff));

        assert!(snap.revokes(1_699_999_999), "issued before the sign-out");
        assert!(!snap.revokes(1_700_000_000), "issued in the same second");
        assert!(!snap.revokes(1_700_000_001), "issued after the sign-out");
    }
}
