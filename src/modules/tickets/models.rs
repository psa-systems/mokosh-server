//! Re-export of the shared tickets DTOs from `mokosh-types`.
//! See [`mokosh_types`] and PMS-129.

pub use mokosh_types::tickets::*;

/// PMS-1087: the SLA state of a ticket as `GET /tickets/{id}/sla`
/// answers it, on both planes. The three live states and
/// `not_applicable` are `mokosh_types::tickets::SlaStatus` under the
/// same snake_case names, computed by `compute_sla_status` so the
/// customer's badge and the agent's badge cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketSlaState {
    OnTrack,
    Warning,
    Breached,
    NotApplicable,
}

impl From<mokosh_types::tickets::SlaStatus> for TicketSlaState {
    fn from(s: mokosh_types::tickets::SlaStatus) -> Self {
        use mokosh_types::tickets::SlaStatus;
        match s {
            SlaStatus::OnTrack => Self::OnTrack,
            SlaStatus::Warning => Self::Warning,
            SlaStatus::Breached => Self::Breached,
            SlaStatus::NotApplicable => Self::NotApplicable,
        }
    }
}

/// PMS-1087: both SLA legs a customer cares about (first response and
/// resolution) with the target and, once reached, the actual event
/// time, so a page can render target against actual. `closed_at` is
/// here because it is what collapses the state to `not_applicable`.
/// A ticket with no policy answers nulls rather than a placeholder
/// target. Nothing internal rides along: no policy id, no escalation
/// chain, no business-hours calendar; the contact arm and the staff
/// arm answer the same shape.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TicketSlaResponse {
    pub sla_due_date: Option<chrono::DateTime<chrono::Utc>>,
    pub first_response_due: Option<chrono::DateTime<chrono::Utc>>,
    pub first_response_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resolution_due: Option<chrono::DateTime<chrono::Utc>>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    pub closed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: TicketSlaState,
    /// The ticket's current status name, so the badge has its context
    /// without a second fetch.
    pub status_name: String,
}
