//! Audit log DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct AuditLogEntryResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<Uuid>,
    pub old_values: Option<serde_json::Value>,
    pub new_values: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// One change-history entry for a single record, derived from `audit_log`.
/// `changed_fields` is the set of columns that differ between the before and
/// after snapshots (noise columns like `updated_at` are dropped), so a detail
/// page can render "Updated (description, status)" without parsing raw JSON.
/// Surfaced by the per-record history endpoint (PMS-182/184/185).
#[derive(Debug, Clone, Serialize)]
pub struct EntityHistoryEntry {
    pub id: Uuid,
    pub action: String,
    pub user_id: Option<Uuid>,
    pub changed_fields: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct AuditLogFilter {
    pub user_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub entity_type: Option<String>,
    #[validate(length(max = 100))]
    pub action: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}
