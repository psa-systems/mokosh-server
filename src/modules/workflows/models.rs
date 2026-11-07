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
// SPEC-7.152: only these three trigger names are recognised by the service.
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
    // SPEC-7.147: trigger_event is validated as a string of length 1..=50.
    #[validate(length(min = 1, max = 50))]
    pub trigger_event: String,
    // SPEC-7.148: name is validated as a string of length 1..=200.
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    pub description: Option<String>,
    /// AND across keys, IN across array values. See the migration
    /// header for the full shape. Empty object matches every new
    /// ticket of that tenant.
    // SPEC-7.149: conditions defaults to {} when omitted from the create request.
    // SPEC-7.1048: conditions and actions JSON are not validated on write.
    #[serde(default = "default_empty_object")]
    pub conditions: serde_json::Value,
    /// Applied in iteration order. See the migration header for the
    /// full shape.
    // SPEC-7.149: actions defaults to {} when omitted from the create request.
    #[serde(default = "default_empty_object")]
    pub actions: serde_json::Value,
    // SPEC-7.150: priority defaults to 100 when omitted from the create request.
    #[serde(default = "default_priority")]
    pub priority: i32,
    // SPEC-7.150: is_active defaults to true when omitted from the create request.
    #[serde(default = "default_true")]
    pub is_active: bool,
}

// SPEC-7.154: this DTO has no trigger_event field at all, so an existing rule's
// trigger event is immutable after creation (it cannot be changed via update).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateWorkflowRuleRequest {
    // SPEC-7.151: on update, name (when Some) must still satisfy length 1..=200.
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
