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

/// PMS-974: who may edit a ticket note, the tenant setting
/// `tickets/note_editing`. This is the WHO gate only; whether a given row may
/// be edited at all (a customer's words, an emailed public note) is the row's
/// state and `TicketService::note_edit_block` answers it regardless of policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoteEditPolicy {
    /// Nobody edits a note, the author included. A note is append-only.
    Off,
    /// The PMS-931 rule and the default: the author, or an admin.
    #[default]
    AuthorOrAdmin,
    /// The author, or anyone who can manage users (`manager` and above).
    AuthorOrManager,
}

impl NoteEditPolicy {
    /// The stored spelling, which `validate_setting_value` refuses anything
    /// outside of. `None` for a value that is none of them.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "author_or_admin" => Some(Self::AuthorOrAdmin),
            "author_or_manager" => Some(Self::AuthorOrManager),
            _ => None,
        }
    }

    /// The stored spelling of this policy.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::AuthorOrAdmin => "author_or_admin",
            Self::AuthorOrManager => "author_or_manager",
        }
    }

    /// May `user` edit a note `author` wrote under this policy? The row's own
    /// state is not consulted here; see `TicketService::note_editable_by`.
    pub fn permits(self, user: &mokosh_types::auth::CurrentUser, author: uuid::Uuid) -> bool {
        match self {
            Self::Off => false,
            Self::AuthorOrAdmin => user.id == author || user.role.is_admin(),
            Self::AuthorOrManager => user.id == author || user.role.can_manage_users(),
        }
    }
}

#[cfg(test)]
mod note_edit_policy_tests {
    use super::NoteEditPolicy;

    #[test]
    fn every_policy_round_trips_through_its_name() {
        for policy in [
            NoteEditPolicy::Off,
            NoteEditPolicy::AuthorOrAdmin,
            NoteEditPolicy::AuthorOrManager,
        ] {
            assert_eq!(NoteEditPolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(NoteEditPolicy::parse("anyone"), None);
        assert_eq!(NoteEditPolicy::default(), NoteEditPolicy::AuthorOrAdmin);
    }
}
