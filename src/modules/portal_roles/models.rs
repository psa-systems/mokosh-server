//! DTOs for the portal-role CRUD surface (prompt 007).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

pub use crate::modules::contacts::PortalRoleSummary;

/// Full portal-role row as returned by GET/{id}, POST, PUT. The list
/// endpoint still returns the lean `PortalRoleSummary` because the SPA
/// grid does not need timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalRole {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub is_builtin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// POST body. The name length cap mirrors `portal_roles.name`
/// (VARCHAR(80)); 64 stays safely under it and matches the SPA's input
/// hint. Empty `capabilities` is allowed at create so the operator can
/// name a shell and fill it in.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreatePortalRoleRequest {
    #[validate(length(min = 1, max = 64))]
    pub name: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// PUT body. Semantically a partial update: either field left `None`
/// keeps its existing value. Empty `capabilities` (as opposed to
/// `None`) is rejected server-side because a role with no capability
/// grants nothing and the SPA has no way to reason about it.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdatePortalRoleRequest {
    #[validate(length(min = 1, max = 64))]
    pub name: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

/// One human-facing capability label. `key` matches an entry in
/// `contact_portal::capabilities::ALL_CAPABILITIES`; `group` is the UI
/// section header (Tickets, Invoices, ...). `description` is the
/// one-sentence subtitle rendered under the checkbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDescriptor {
    pub key: String,
    pub label: String,
    pub group: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListCapabilitiesResponse {
    pub capabilities: Vec<CapabilityDescriptor>,
}
