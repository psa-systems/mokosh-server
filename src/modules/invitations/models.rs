//! Invitation DTOs (PMS-244).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Roles a tenant admin may grant via an invite. `super_admin` is platform
/// level and deliberately not invitable.
pub const INVITABLE_ROLES: &[&str] = &[
    "admin",
    "manager",
    "technician",
    "dispatcher",
    "sales",
    "finance",
];

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct InvitationResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub status: String,
    pub invited_by: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// PMS-1161: optional team the invitee joins on accept. `None` means a
    /// tenant-wide role invite with no team assignment (the shape PMS-244
    /// originally shipped).
    #[serde(default)]
    pub team_id: Option<Uuid>,
}

/// Slim projection the login path consumes to place an invited user (PMS-244).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingInvite {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    /// PMS-1161: the team the invitee joins on accept. `None` for a
    /// tenant-wide role invite. `Some` for an invite that additionally
    /// enrols them in a team. Read by
    /// [`InvitationsService::accept`](super::service::InvitationsService::accept)
    /// so the team_members INSERT rides in the same transaction as the
    /// invite-accepted mark.
    pub team_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateInvitationRequest {
    #[validate(email)]
    pub email: String,
    /// One of [`INVITABLE_ROLES`]; defaults to `admin` (MAPPS-330: every Mokosh
    /// user is the admin of their own world). Validated in the service (a custom
    /// set check rather than a derive).
    #[serde(default = "default_role")]
    pub role: String,
    /// PMS-1161: optional team the invitee joins on accept. Verified against
    /// the invite's own tenant in
    /// [`InvitationsService::create`](super::service::InvitationsService::create);
    /// a foreign-tenant team is a 422 so the invite cannot silently drop
    /// its team association.
    #[serde(default)]
    pub team_id: Option<Uuid>,
}

fn default_role() -> String {
    "admin".to_string()
}
