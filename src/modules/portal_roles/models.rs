//! DTOs for the portal-role CRUD surface (prompt 007).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

pub use crate::modules::contacts::PortalRoleSummary;

/// Full portal-role row as returned by GET/{id}, POST, PUT. The list
/// endpoint still returns the lean `PortalRoleSummary` because the SPA
/// grid does not need timestamps.
///
/// PMS-929 (prompt 012): `company_id` distinguishes tenant-wide roles
/// (`None`) from Company-scoped ones (`Some(id)`); scope is immutable
/// once set. `#[serde(default)]` for the same forward-compat reason as
/// `PortalRoleSummary`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalRole {
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[serde(default)]
    pub company_id: Option<Uuid>,
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
///
/// PMS-929 (prompt 012): `company_id` is optional; `None` mints a
/// tenant-wide role (existing shape), `Some(id)` mints a role scoped to
/// that Company. Validated server-side that the Company belongs to the
/// caller's tenant.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreatePortalRoleRequest {
    #[validate(length(min = 1, max = 64))]
    pub name: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub company_id: Option<Uuid>,
}

/// PUT body. Semantically a partial update: either field left `None`
/// keeps its existing value. Empty `capabilities` (as opposed to
/// `None`) is rejected server-side because a role with no capability
/// grants nothing and the SPA has no way to reason about it.
///
/// PMS-929 (prompt 012): scope is immutable, so no `company_id` here.
/// A DTO-level omission means a request body carrying that field
/// silently drops it at deserialization; the service also never touches
/// `company_id` on the UPDATE.
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
