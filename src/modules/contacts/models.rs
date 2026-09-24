//! Re-export of the shared contacts DTOs from `mokosh-types`.
//! See [`mokosh_types`] and PMS-129.

pub use mokosh_types::contacts::*;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One row of `GET /api/v1/portal-roles`. The SPA renders `capabilities` as a
/// checkbox list in the role-picker modal + label chips on the
/// contact edit page.
///
/// PMS-929 (prompt 012): `company_id` marks whether the role is
/// tenant-wide (`None`) or scoped to a single Company (`Some(id)`).
/// `#[serde(default)]` so a wire payload from a pre-migration client or
/// a hand-crafted test fixture without the field deserializes to
/// tenant-wide instead of erroring, which matches the historical
/// two-value shape and stays forward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalRoleSummary {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub is_builtin: bool,
    #[serde(default)]
    pub company_id: Option<Uuid>,
    /// MAPPS-635 E: count of contacts currently holding this role
    /// (via `contact_role_assignments`). Populated by the list
    /// handler so the Settings > Contact Roles table can render a
    /// real number in its CONTACTS column instead of the hard-coded
    /// "-". `serde(default)` so a wire payload from a pre-fix
    /// server still deserialises as `0`.
    #[serde(default)]
    pub contacts_count: i64,
}

/// PMS-1187: one access request, as staff read it.
///
/// Carries the note the contact wrote, because the whole point of asking is to
/// say why, and the MSP deciding needs it.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PortalAccessRequestRow {
    pub id: uuid::Uuid,
    pub contact_id: uuid::Uuid,
    pub company_id: Option<uuid::Uuid>,
    pub area: String,
    pub note: Option<String>,
    /// `open`, `granted`, `declined` or `withdrawn`.
    pub status: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub resolved_by_id: Option<uuid::Uuid>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// PMS-1187: how staff answer one.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ResolveAccessRequest {
    /// `true` grants the area's built-in role and closes the request; `false`
    /// closes it without granting. No third value: a request left open is left
    /// open by not calling this.
    pub grant: bool,
}
