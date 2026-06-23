//! PMS-453: saved dashboards DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// One saved dashboard row returned to the SPA. The `layout` blob is
/// passed through verbatim - shape is owned by the SPA so a UI change
/// can ship without a server migration.
#[derive(Debug, Clone, Serialize)]
pub struct SavedDashboardResponse {
    pub id: Uuid,
    pub name: String,
    pub layout: serde_json::Value,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateSavedDashboardRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    /// SPA-owned layout blob. Defaults to `{}` so the SPA can create an
    /// empty dashboard first and populate widgets in a follow-up PATCH.
    #[serde(default)]
    pub layout: serde_json::Value,
    /// When true, the create handler clears any existing default for
    /// the same (tenant, user) inside the same transaction before
    /// inserting the new row, so the partial-unique index never
    /// conflicts.
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateSavedDashboardRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,
    pub layout: Option<serde_json::Value>,
    /// Setting this to `true` promotes the row to default and clears
    /// the previous default in the same transaction. Setting it to
    /// `false` just clears the flag (the user can then PATCH another
    /// row to true). Omitted: untouched.
    pub is_default: Option<bool>,
}
