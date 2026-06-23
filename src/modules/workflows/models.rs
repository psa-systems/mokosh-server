//! PMS-448: workflow rule DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// The set of recognised trigger names. The data model carries the
/// event as a VARCHAR so future surfaces (e.g. `time_entry.created`,
/// `invoice.paid`) can land without a schema migration; the service
/// gates which ones the executor knows how to fire.
pub const TRIGGER_TICKET_CREATED: &str = "ticket.created";
/// PMS-448 phase 2: fires when a ticket's `status_id` moves.
/// Conditions can match on the new ticket dimensions plus
/// `from_status_id` / `to_status_id` so a rule can target only
/// "moved into 'in-progress'" (route to a senior tech) or "moved
/// into 'closed'" (auto-add a follow-up note).
pub const TRIGGER_TICKET_STATUS_CHANGED: &str = "ticket.status_changed";
/// PMS-448 phase 2: fires when a ticket's `priority_id` moves.
/// Same shape as status_changed: conditions add `from_priority_id`
/// / `to_priority_id` so a rule can react specifically to escalations.
pub const TRIGGER_TICKET_PRIORITY_CHANGED: &str = "ticket.priority_changed";

/// Service-side allow-list of triggers the Phase 2 executor knows
/// how to fire. Anything else is rejected at create-rule time so
/// an operator does not silently land a never-firing rule.
pub const RECOGNISED_TRIGGERS: &[&str] = &[
    TRIGGER_TICKET_CREATED,
    TRIGGER_TICKET_STATUS_CHANGED,
    TRIGGER_TICKET_PRIORITY_CHANGED,
];

#[derive(Debug, Clone, Serialize)]
pub struct WorkflowRuleResponse {
    pub id: Uuid,
    pub trigger_event: String,
    pub name: String,
    pub description: Option<String>,
    pub conditions: serde_json::Value,
    pub actions: serde_json::Value,
    pub priority: i32,
    pub is_active: bool,
    pub created_by_id: Uuid,
    pub created_by_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateWorkflowRuleRequest {
    /// Phase 1 only accepts `ticket.created`. The service rejects
    /// anything else with 400 so an operator does not silently
    /// create a never-firing rule.
    #[validate(length(min = 1, max = 50))]
    pub trigger_event: String,
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    pub description: Option<String>,
    /// AND across keys, IN across array values. See the migration
    /// header for the full shape. Empty object matches every new
    /// ticket of that tenant.
    #[serde(default = "default_empty_object")]
    pub conditions: serde_json::Value,
    /// Applied in iteration order. See the migration header for the
    /// full shape.
    #[serde(default = "default_empty_object")]
    pub actions: serde_json::Value,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateWorkflowRuleRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub conditions: Option<serde_json::Value>,
    pub actions: Option<serde_json::Value>,
    pub priority: Option<i32>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkflowRuleRunResponse {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub rule_name: Option<String>,
    pub entity_type: String,
    pub entity_id: Uuid,
    pub applied_actions: serde_json::Value,
    pub error: Option<String>,
    pub ran_at: DateTime<Utc>,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}

fn default_priority() -> i32 {
    100
}

fn default_true() -> bool {
    true
}
