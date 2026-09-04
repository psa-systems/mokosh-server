//! Time-tracking DTOs.

// `ApprovalStatus` exposes `from_str(&str) -> Option<Self>` as a
// deliberate infallible-style parser API matching the other domain
// enums; it intentionally does not implement `std::str::FromStr`.
#![allow(clippy::should_implement_trait)]

use crate::tickets::BillingStatus;
use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Per-entry approval state for time entries. Mirrors the
/// `approval_status` column enum (`draft|pending|approved|rejected`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Draft,
    #[default]
    Pending,
    Approved,
    Rejected,
}

impl ApprovalStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

// ============================================================================
// Work types
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct WorkTypeResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub default_billable: bool,
    pub default_rate: Option<Decimal>,
    pub is_active: bool,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertWorkTypeRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "crate::default_true")]
    pub default_billable: bool,
    #[validate(custom(function = crate::validation::validate_rate))]
    pub default_rate: Option<Decimal>,
    #[serde(default = "crate::default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub sort_order: i32,
}

// ============================================================================
// Time entries
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TimeEntryResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub date: NaiveDate,
    pub start_time: Option<NaiveTime>,
    pub end_time: Option<NaiveTime>,
    /// Worked (actual) time. Canonical going forward and never mutated by
    /// rounding (PMS-395). Currently tracks `duration_minutes`.
    pub duration_minutes: i32,
    /// PMS-395: actual time spent on the entry. Mirror of `duration_minutes`
    /// during the one-release overlap; reports treat this as canonical.
    pub worked_minutes: i32,
    /// PMS-395: time billed, independent of `worked_minutes`. Can exceed
    /// worked time (minimum increments, one update billed across several
    /// clients) or fall below it (internal absorption). `total_amount` is
    /// priced on this figure. NULL only for legacy rows that predate the
    /// backfill, in which case clients fall back to the rounded worked time.
    pub billable_minutes: Option<i32>,
    pub work_type_id: Uuid,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    /// Classifier for the kind of work (PMS-394): `ticketed` | `project` |
    /// `general`. Lets reports split true overhead (`general`) from
    /// client-attributable work. Derived server-side from the presence of
    /// `ticket_id` / `project_id` when omitted.
    pub work_category: Option<String>,
    /// Optional link to a project task (PMS-51). Exposed so a client editing
    /// an entry can read and re-send the current task link; a partial PUT that
    /// omits `task_id` preserves it server-side (PMS-328).
    pub task_id: Option<Uuid>,
    /// PMS-942: `client` or `employee`. The axis every billing and approval
    /// rule that differs between a customer's work and the MSP's own time
    /// keys on, rather than each one re-deriving it from the company.
    pub entry_kind: String,
    /// PMS-942: null on employee time recorded with no company at all.
    pub company_id: Option<Uuid>,
    pub notes: Option<String>,
    pub is_billable: bool,
    pub billing_status: BillingStatus,
    pub hourly_rate: Option<Decimal>,
    pub total_amount: Option<Decimal>,
    pub approval_status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Joined work-item names (PMS-332), so the client renders the Work Item
    /// column without per-row lookups. Each is null when the entry has no link
    /// of that kind, or when the linked row is not visible (e.g. RLS-scoped).
    pub ticket_number: Option<String>,
    pub ticket_title: Option<String>,
    pub project_name: Option<String>,
    pub task_title: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct TimeEntryFilter {
    pub user_id: Option<Uuid>,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub date_from: Option<NaiveDate>,
    pub date_to: Option<NaiveDate>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateTimeEntryRequest {
    /// Only super_admin / admin / manager can attribute time to a
    /// different user. The route handler enforces; service trusts the
    /// caller.
    pub user_id: Uuid,
    pub date: NaiveDate,
    pub start_time: Option<NaiveTime>,
    pub end_time: Option<NaiveTime>,
    /// Either supply (start, end) and let the service compute the
    /// minutes, or supply `duration_minutes` directly. Capped at 1440
    /// (24h) so a single entry can never alone exceed a day, regardless
    /// of the per-tenant day cap (PMS-396).
    #[validate(range(min = 1, max = 1440))]
    pub duration_minutes: Option<i32>,
    /// PMS-395: worked (actual) minutes. When supplied it takes precedence
    /// over `duration_minutes` / (start, end) as the worked figure. Capped
    /// at 1440 (24h) like `duration_minutes`.
    #[validate(range(min = 1, max = 1440))]
    #[serde(default)]
    pub worked_minutes: Option<i32>,
    /// PMS-395: billed minutes. When omitted the service defaults it to the
    /// rounded worked time for billable entries (pre-change behavior), 0 for
    /// non-billable. May legitimately exceed worked time. Capped at 1440.
    #[validate(range(min = 0, max = 1440))]
    #[serde(default)]
    pub billable_minutes: Option<i32>,
    pub work_type_id: Uuid,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    /// Work classifier (PMS-394): `ticketed` | `project` | `general`. When
    /// omitted the service derives it from `ticket_id` / `project_id`
    /// (general when both absent). Supplying `ticketed` with no `ticket_id`
    /// is a 400.
    pub work_category: Option<String>,
    /// Optional link to a project task (PMS-51). Approved time against a
    /// task rolls up into the task's and project's actual hours.
    pub task_id: Option<Uuid>,
    /// PMS-942: whose time this is. `client` is work booked against a customer
    /// and eligible for invoicing; `employee` is the MSP's own time and never
    /// reaches a client invoice.
    ///
    /// Omitted lets the service derive it, which is what keeps an existing
    /// client working: a company plus a ticket or a project is client work,
    /// the tenant's own internal company (PMS-413) is employee time, and no
    /// company at all is employee time.
    #[serde(default)]
    pub entry_kind: Option<String>,
    /// PMS-942: optional, because employee time has no client to name. A
    /// `client` entry without one is a 400. Employee time may still name the
    /// tenant's own internal company, which is what MAPPS-243 sends today.
    #[serde(default)]
    pub company_id: Option<Uuid>,
    pub notes: Option<String>,
    #[serde(default = "crate::default_true")]
    pub is_billable: bool,
    #[validate(custom(function = crate::validation::validate_rate))]
    pub hourly_rate: Option<Decimal>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateTimeEntryRequest {
    pub date: Option<NaiveDate>,
    pub start_time: Option<NaiveTime>,
    pub end_time: Option<NaiveTime>,
    /// Capped at 1440 (24h); a single entry can never alone exceed a day
    /// regardless of the per-tenant day cap (PMS-396).
    #[validate(range(min = 1, max = 1440))]
    pub duration_minutes: Option<i32>,
    /// PMS-395: worked (actual) minutes. Takes precedence over
    /// `duration_minutes` / (start, end) when supplied.
    #[validate(range(min = 1, max = 1440))]
    #[serde(default)]
    pub worked_minutes: Option<i32>,
    /// PMS-395: billed minutes. When omitted the existing value is preserved;
    /// if none was ever set it defaults to the rounded worked time for
    /// billable entries. `total_amount` is recomputed from this figure.
    #[validate(range(min = 0, max = 1440))]
    #[serde(default)]
    pub billable_minutes: Option<i32>,
    pub work_type_id: Option<Uuid>,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    /// Work classifier (PMS-394): `ticketed` | `project` | `general`. When
    /// omitted the service re-derives it from the resulting `ticket_id` /
    /// `project_id`.
    pub work_category: Option<String>,
    pub task_id: Option<Uuid>,
    pub notes: Option<String>,
    pub is_billable: Option<bool>,
    #[validate(custom(function = crate::validation::validate_rate))]
    pub hourly_rate: Option<Decimal>,
}

// ============================================================================
// Timesheets (week aggregation over time_entries)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TimesheetSummaryResponse {
    pub user_id: Uuid,
    pub week_start: NaiveDate,
    /// PMS-395: sum of `worked_minutes` (actual time) across the week's
    /// entries, falling back to `duration_minutes` for legacy rows.
    pub total_minutes: i64,
    /// PMS-395: sum of `billable_minutes` (time billed) across the week's
    /// entries. No longer just the worked time of billable-flagged entries:
    /// it can diverge from `total_minutes` per entry.
    pub billable_minutes: i64,
    pub entry_count: i64,
    /// Week-level rollup of per-entry approval_status: "rejected" if any
    /// entry is rejected, "approved" if all are, else "pending".
    ///
    /// DEBT: there is no real `submitted` state - the schema enum is
    /// pending|approved|rejected only. The client renders `pending` with
    /// `entry_count > 0` as "awaiting approval", so a submitted week is
    /// visibly distinct from a never-touched one. Add a `submitted` state
    /// post-M1 if approval needs a true draft/submitted boundary.
    pub approval_status: String,
    /// PMS-506: user_id of the reviewer who decided the week (set on
    /// approve_week / reject_week; NULL while pending). Approve and
    /// reject both run a single UPDATE against every entry in the
    /// week, so the reviewer id is identical across the rolled rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by_id: Option<Uuid>,
    /// PMS-506: timestamp the week was approved or rejected (NULL
    /// while pending). Lets the history view label "Approved by X on Y".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    /// PMS-506: rejection reason carried through from
    /// reject_week (NULL for approved / pending rows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct TimesheetFilter {
    pub user_id: Option<Uuid>,
    pub week: Option<NaiveDate>,
    /// PMS-506: rolled approval status filter. One of
    /// `pending | approved | rejected | all`. Missing / `all` returns
    /// every status. Validated server-side; unknown values are 422.
    #[serde(default)]
    #[validate(length(min = 1, max = 16))]
    pub status: Option<String>,
    /// PMS-506: inclusive Monday-aligned start of a multi-week range.
    /// When `from` is set the `week` field is ignored and the scan
    /// covers `[from, to]`. Server caps the span at 26 weeks.
    #[serde(default)]
    pub from: Option<NaiveDate>,
    /// PMS-506: inclusive Monday-aligned end of a multi-week range.
    /// When `to` is unset but `from` is, `to` defaults to `from`
    /// (single-week behaviour). Server caps the span at 26 weeks.
    #[serde(default)]
    pub to: Option<NaiveDate>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RejectTimesheetRequest {
    #[validate(length(min = 1, max = 1000))]
    pub reason: String,
}

// ============================================================================
// Active timers
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct ActiveTimerResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub company_id: Option<Uuid>,
    pub work_type_id: Option<Uuid>,
    pub notes: Option<String>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct StartTimerRequest {
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub company_id: Option<Uuid>,
    pub work_type_id: Option<Uuid>,
    pub notes: Option<String>,
}

// ============================================================================
// Time rounding rules
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TimeRoundingRuleResponse {
    pub id: Uuid,
    pub name: String,
    pub increment_minutes: i32,
    pub rounding_method: String,
    pub minimum_minutes: i32,
    pub is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertTimeRoundingRuleRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(range(min = 1, max = 240))]
    pub increment_minutes: i32,
    /// "up" | "down" | "nearest"
    pub rounding_method: String,
    #[validate(range(min = 0))]
    #[serde(default)]
    pub minimum_minutes: i32,
    #[serde(default)]
    pub is_default: bool,
}

// ============================================================================
// PMS-950 work day: clock in and out, breaks, and the day's breakdown
// ============================================================================

/// One segment of a person's working day: `work` from clock-in to clock-out
/// (or to the start of a break), `break` between two `work` segments. The day
/// is derived from its segments rather than stored, so nothing here can
/// disagree with what the person actually did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkDaySegmentResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    /// The day the segment belongs to. Kept across midnight, so a night shift
    /// stays on the day it started.
    pub date: NaiveDate,
    /// `work` or `break`.
    pub kind: String,
    pub started_at: DateTime<Utc>,
    /// `None` while the segment is open.
    pub ended_at: Option<DateTime<Utc>>,
    /// Elapsed minutes; an open segment counts up to now.
    pub minutes: i64,
}

/// The body of a clock-in. `date` is the client's local day, the way a time
/// entry carries the date the client sent; absent, the UTC date of the
/// clock-in.
#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct ClockInRequest {
    pub date: Option<NaiveDate>,
}

/// `GET /workday`: which day, and whose. `date` absent means the day of the
/// open segment if there is one, else today (UTC), so a reload finds the clock
/// where it was left. `user_id` is honoured for an admin and ignored for
/// anyone else, who sees their own day.
#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct WorkDayQuery {
    pub date: Option<NaiveDate>,
    pub user_id: Option<Uuid>,
}

/// One ticket's share of the day, summed over the day's entries naming it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkDayTicketLine {
    pub ticket_id: Uuid,
    pub ticket_number: Option<String>,
    pub ticket_title: Option<String>,
    pub minutes: i64,
    pub entry_count: i64,
}

/// One project's share of the day: entries naming the project and no ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkDayProjectLine {
    pub project_id: Uuid,
    pub project_name: Option<String>,
    pub minutes: i64,
    pub entry_count: i64,
}

/// A bucket with no identity of its own: Administrative, or Unattached.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkDayBucket {
    pub minutes: i64,
    pub entry_count: i64,
}

/// The day's `time_entries` read by what they are attached to. The four parts
/// partition the day's entries, so their minutes sum to `logged_minutes`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkDayBreakdown {
    pub tickets: Vec<WorkDayTicketLine>,
    pub projects: Vec<WorkDayProjectLine>,
    /// The MSP's own time: `entry_kind = 'employee'` (PMS-942). Paperwork for
    /// your employer is paid company time that belongs on the timesheet and on
    /// no client.
    pub administrative: WorkDayBucket,
    /// Client work naming neither a ticket nor a project. PMS-942 says a
    /// billable client call logged without a ticket is the client's time and
    /// not the MSP's, so it is not filed under Administrative.
    pub unattached: WorkDayBucket,
}

/// A person's day: the clock and the work, as two readings of the same rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkDayResponse {
    pub user_id: Uuid,
    pub date: NaiveDate,
    /// A segment on this day is still open.
    pub is_clocked_in: bool,
    /// The open segment is a break.
    pub on_break: bool,
    /// Whether this employer tracks breaks (`timesheets/track_breaks`, PMS-943).
    /// With it off no break control is offered and the day is one segment.
    pub track_breaks: bool,
    pub segments: Vec<WorkDaySegmentResponse>,
    /// Minutes in `work` segments, an open one counted to now.
    pub clocked_minutes: i64,
    /// Minutes in `break` segments.
    pub break_minutes: i64,
    /// Minutes across the day's time entries (`worked_minutes`).
    pub logged_minutes: i64,
    /// `clocked_minutes - logged_minutes`. Positive is clocked time nobody has
    /// logged yet; negative is more logged than clocked. Reported, not
    /// resolved: eight hours clocked against six logged is the normal case.
    pub unlogged_minutes: i64,
    pub breakdown: WorkDayBreakdown,
}
