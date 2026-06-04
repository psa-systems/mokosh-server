//! Time-tracking DTOs.

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

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
    #[serde(default = "default_true")]
    pub default_billable: bool,
    pub default_rate: Option<Decimal>,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub sort_order: i32,
}

fn default_true() -> bool {
    true
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
    pub duration_minutes: i32,
    pub work_type_id: Uuid,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub company_id: Uuid,
    pub notes: Option<String>,
    pub is_billable: bool,
    pub billing_status: String,
    pub hourly_rate: Option<Decimal>,
    pub total_amount: Option<Decimal>,
    pub approval_status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    /// minutes, or supply `duration_minutes` directly.
    pub duration_minutes: Option<i32>,
    pub work_type_id: Uuid,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub company_id: Uuid,
    pub notes: Option<String>,
    #[serde(default = "default_true")]
    pub is_billable: bool,
    pub hourly_rate: Option<Decimal>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateTimeEntryRequest {
    pub date: Option<NaiveDate>,
    pub start_time: Option<NaiveTime>,
    pub end_time: Option<NaiveTime>,
    pub duration_minutes: Option<i32>,
    pub work_type_id: Option<Uuid>,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub notes: Option<String>,
    pub is_billable: Option<bool>,
    pub hourly_rate: Option<Decimal>,
}

// ============================================================================
// Timesheets (week aggregation over time_entries)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TimesheetSummaryResponse {
    pub user_id: Uuid,
    pub week_start: NaiveDate,
    pub total_minutes: i64,
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
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct TimesheetFilter {
    pub user_id: Option<Uuid>,
    pub week: Option<NaiveDate>,
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
