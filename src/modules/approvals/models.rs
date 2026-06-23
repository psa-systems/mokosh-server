//! PMS-451: ticket approval DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalResponse {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub requested_by_id: Uuid,
    /// Resolved display name (first_name + last_name) of the
    /// requester. LEFT JOIN'd so a deleted user surfaces as `None`
    /// instead of breaking the read.
    pub requested_by_name: Option<String>,
    pub approver_user_id: Option<Uuid>,
    pub approver_user_name: Option<String>,
    pub approver_role: Option<String>,
    pub status: String,
    pub notes: Option<String>,
    pub decision_notes: Option<String>,
    pub decided_by_id: Option<Uuid>,
    pub decided_by_name: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateApprovalRequest {
    /// Either `approver_user_id` (assign-by-id) or `approver_role`
    /// (assign-by-role) must be set. Both-set or neither-set is a
    /// 422 surfaced from the service before reaching the DB CHECK so
    /// the SPA gets a clear field-level error.
    pub approver_user_id: Option<Uuid>,
    #[validate(length(max = 50))]
    pub approver_role: Option<String>,
    /// Optional rationale shown to the approver. Long-form because
    /// the approver may need context that does not fit in a comment.
    #[validate(length(max = 4000))]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct DecideApprovalRequest {
    /// "approve" or "reject". Rejected by the service if anything
    /// else.
    #[validate(length(min = 4, max = 16))]
    pub decision: String,
    #[validate(length(max = 4000))]
    pub decision_notes: Option<String>,
}
