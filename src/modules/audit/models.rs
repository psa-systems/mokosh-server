//! Audit log DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct AuditLogEntryResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
    /// Resolved actor display name: `"<first_name> <last_name>"` for the
    /// user identified by `user_id`. `None` when the row is system-issued
    /// (`user_id` NULL) or when the JIT-created user has not yet filled
    /// in their name through the onboarding screen. The SPA renders this
    /// when set and falls back to "System" when null, instead of leaking
    /// the bare UUID.
    pub user_name: Option<String>,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<Uuid>,
    /// Resolved display name for the row identified by
    /// (`entity_type`, `entity_id`). Each entity type maps to whichever
    /// column its UI uses as the human label (`name`, `invoice_number`,
    /// `T<ticket_number>`, etc.). `None` when the entity was deleted, an
    /// unrecognized entity_type slips through, or the row's natural-key
    /// column is empty.
    pub entity_name: Option<String>,
    pub old_values: Option<serde_json::Value>,
    pub new_values: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
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
