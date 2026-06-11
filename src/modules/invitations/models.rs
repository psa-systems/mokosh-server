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
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateInvitationRequest {
    #[validate(email)]
    pub email: String,
    /// One of [`INVITABLE_ROLES`]; defaults to `technician`. Validated in the
    /// service (a custom set check rather than a derive).
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "technician".to_string()
}
