//! PMS-451: ticket approval DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalResponse {
    pub id: Uuid,
    /// PMS-470: the parent entity kind. `ticket` for backwards-
    /// compatible phase-1 rows; `change_request` / `quote` /
    /// `time_entry` for the new polymorphic targets.
    pub target: String,
    /// PMS-470: the parent entity's PK. For `target='ticket'` this
    /// equals `ticket_id`; for other targets the legacy ticket_id
    /// is null and `entity_id` is the only id consumers should read.
    pub entity_id: Uuid,
    /// PMS-470: kept for backwards-compatible reads from phase-1
    /// consumers. `None` on non-ticket rows; consumers that need to
    /// be polymorphic should read `(target, entity_id)` instead.
    pub ticket_id: Option<Uuid>,
    /// PMS-940: the parent's human handle - `tickets.ticket_number`
    /// (`T000123`) or `quotes.quote_number`. `None` for the two
    /// targets that have no number column (change_request,
    /// time_entry) and for a parent that has been deleted.
    pub entity_reference: Option<String>,
    /// PMS-940: the parent's title, so the approvals queue can name
    /// what it is asking about instead of printing `entity_id`. The
    /// three titled targets return their title; a `time_entry` has
    /// no title, so it returns the duration and the date it covers.
    /// LEFT JOIN'd, so a deleted parent surfaces as `None` rather
    /// than dropping the approval from the queue.
    pub entity_label: Option<String>,
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

/// PMS-470: parent entity kinds the approvals surface supports.
/// Each variant maps 1:1 to the `target` column's CHECK values; the
/// route layer mounts a per-entity prefix that resolves into this
/// enum before calling into the generic service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalTarget {
    Ticket,
    ChangeRequest,
    Quote,
    TimeEntry,
}

impl ApprovalTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ticket => "ticket",
            Self::ChangeRequest => "change_request",
            Self::Quote => "quote",
            Self::TimeEntry => "time_entry",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ticket" => Some(Self::Ticket),
            "change_request" => Some(Self::ChangeRequest),
            "quote" => Some(Self::Quote),
            "time_entry" => Some(Self::TimeEntry),
            _ => None,
        }
    }
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
