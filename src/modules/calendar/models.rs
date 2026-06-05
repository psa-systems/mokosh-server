//! Calendar / scheduling DTOs added in the PMS-58 story.

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// ============================================================================
// Appointments
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct AppointmentResponse {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub appointment_type: String,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub task_id: Option<Uuid>,
    pub company_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub assigned_to_id: Uuid,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub all_day: bool,
    pub timezone: String,
    pub status: String,
    pub location: Option<String>,
    /// RFC 5545 RRULE string when this is a recurring series master
    /// (e.g. `FREQ=DAILY;COUNT=3`). `None` for a one-off appointment or
    /// for an expanded occurrence instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence_rule: Option<String>,
    /// Set on an expanded occurrence instance to the id of the series
    /// master it was generated from. `None` on stored rows. Lets a
    /// client tell a virtual instance apart from a persisted row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence_parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAppointmentRequest {
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    pub description: Option<String>,
    #[serde(default = "default_other")]
    pub appointment_type: String,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub task_id: Option<Uuid>,
    pub company_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub assigned_to_id: Uuid,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    #[serde(default)]
    pub all_day: bool,
    #[serde(default = "default_utc")]
    pub timezone: String,
    pub location: Option<String>,
    /// Optional RFC 5545 RRULE (e.g. `FREQ=WEEKLY;BYDAY=MO`). Stored
    /// verbatim; occurrences are expanded in-memory at read time, never
    /// materialised as rows. A `DTSTART` line is NOT expected here - the
    /// series is anchored on this appointment's `start_time`.
    pub recurrence_rule: Option<String>,
}

fn default_other() -> String {
    "other".into()
}
fn default_utc() -> String {
    "UTC".into()
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateAppointmentRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub appointment_type: Option<String>,
    pub assigned_to_id: Option<Uuid>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub all_day: Option<bool>,
    pub timezone: Option<String>,
    pub status: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct AppointmentFilter {
    pub user_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub appointment_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

// ============================================================================
// User availability
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct UserAvailabilityResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub day_of_week: i32,
    pub start_time: NaiveTime,
    pub end_time: NaiveTime,
    pub is_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AvailabilityWindow {
    #[validate(range(min = 0, max = 6))]
    pub day_of_week: i32,
    pub start_time: NaiveTime,
    pub end_time: NaiveTime,
    #[serde(default = "default_true")]
    pub is_available: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ReplaceAvailabilityRequest {
    pub windows: Vec<AvailabilityWindow>,
}

// ============================================================================
// Time off
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TimeOffResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
    pub approved_by_id: Option<Uuid>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateTimeOffRequest {
    pub user_id: Uuid,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    /// "vacation" | "sick" | "personal" | "holiday" | "other"
    #[serde(rename = "type")]
    pub kind: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct TimeOffFilter {
    pub user_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub status: Option<String>,
    pub from: Option<NaiveDate>,
    pub to: Option<NaiveDate>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ApproveTimeOffRequest {
    /// "approved" | "rejected"
    pub status: String,
}

// ============================================================================
// On-call
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct OnCallScheduleResponse {
    pub id: Uuid,
    pub name: String,
    pub team_id: Option<Uuid>,
    pub rotation_type: String,
    pub rotation_config: serde_json::Value,
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertOnCallScheduleRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub team_id: Option<Uuid>,
    #[serde(default = "default_weekly")]
    pub rotation_type: String,
    #[serde(default)]
    pub rotation_config: serde_json::Value,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_weekly() -> String {
    "weekly".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct OnCallNowResponse {
    /// Each entry names a schedule + the user who is currently on call
    /// for it. `rotation_config` schemas are owner-defined; the
    /// resolver here picks the first user_id from
    /// `rotation_config.user_ids[]` deterministically. Real rotation
    /// math (round-robin by week, day-of-week overrides, etc.) is the
    /// next PMS-63 commit.
    pub schedule_id: Uuid,
    pub schedule_name: String,
    pub on_call_user_id: Option<Uuid>,
}

// ============================================================================
// Dispatch view (PMS-58)
// ============================================================================

/// Query for the dispatch board. `from`/`to` bound the window the
/// aggregation covers; `assigned_to_id` optionally narrows appointments
/// and availability to one technician.
#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct DispatchFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub assigned_to_id: Option<Uuid>,
}

/// Aggregated technician-dispatch view for a date range. Combines the
/// four scheduling surfaces a dispatcher needs on one board:
/// appointments (recurring series expanded in-memory), per-user weekly
/// availability windows, approved time off, and current on-call
/// coverage.
#[derive(Debug, Clone, Serialize)]
pub struct DispatchResponse {
    /// Appointments overlapping the range, with recurring series
    /// expanded to concrete occurrence instances.
    pub appointments: Vec<AppointmentResponse>,
    /// Weekly availability windows. Scoped to `assigned_to_id` when the
    /// filter sets it, otherwise every user in the tenant.
    pub availability: Vec<UserAvailabilityResponse>,
    /// Approved time off overlapping the range (pending / rejected
    /// requests are excluded - they do not block dispatch).
    pub time_off: Vec<TimeOffResponse>,
    /// Who is on call right now, one entry per active schedule.
    pub on_call: Vec<OnCallNowResponse>,
}
