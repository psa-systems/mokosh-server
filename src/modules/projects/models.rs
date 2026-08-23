//! Projects + tasks DTOs.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Tolerant deserialization for the optional `Decimal` budget fields (PMS-324).
///
/// The mokosh-apps client posts budgets as JSON *numbers* (`8.5`), while the
/// integration suite and other callers post numeric *strings* (`"8.5"`).
/// rust_decimal's default `serde` impl only accepts strings, so a numeric
/// budget was rejected by the `Json` extractor as a 422 before validation even
/// ran (the "Budget Hours request failed" bug). Accept a JSON number, a numeric
/// string, or null; a number is parsed from its exact textual form (not via
/// `f64`) so no floating-point error is introduced.
mod decimal_opt {
    use rust_decimal::Decimal;
    use serde::{Deserialize, Deserializer};
    use std::str::FromStr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Decimal>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::String(s) => {
                let s = s.trim();
                if s.is_empty() {
                    Ok(None)
                } else {
                    Decimal::from_str(s).map(Some).map_err(Error::custom)
                }
            }
            serde_json::Value::Number(n) => Decimal::from_str(&n.to_string())
                .map(Some)
                .map_err(Error::custom),
            other => Err(Error::custom(format!(
                "expected a number, decimal string, or null, got {other}"
            ))),
        }
    }
}

/// PMS-894: the tenant-wide project totals, so a client can render them
/// without fetching every project.
///
/// The SPA's project list computed its Active / On hold / Completed cards and
/// its budget sum from the rows it had fetched, which meant the cards reported
/// one page. The counts alone are already answerable with
/// `?status=X&per_page=1` and `meta.total`; the sum is not, and a sum is the
/// one a page cannot approximate from a page.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectSummaryResponse {
    /// Count per `projects.status`, one entry per status actually present.
    /// Absent rather than zero for a status no project holds: the set of
    /// statuses is the data's, not this endpoint's to assert.
    pub counts_by_status: std::collections::BTreeMap<String, i64>,
    /// Total of `budget_amount` across every project in the tenant, NULL
    /// budgets excluded. Serialised as a string, like every other money field
    /// on the wire, so no client parses it through a float.
    pub total_budget: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub project_number: Option<String>,
    pub company_id: Option<Uuid>,
    /// Name of the owning company, resolved via a tenant-scoped LEFT join on
    /// `companies` (PMS-335). `None` when the project has no `company_id` (or
    /// the company row is gone), so the DTO carries the client name without an
    /// N+1 lookup per project.
    pub company_name: Option<String>,
    pub contract_id: Option<Uuid>,
    /// Legacy free-string classification, kept for one release (PMS-322).
    /// Prefer `project_type_id`, which references the `project_types` lookup.
    pub project_type: String,
    /// FK into the tenant-scoped `project_types` lookup. `None` only for rows
    /// whose legacy `project_type` string had no matching lookup row.
    pub project_type_id: Option<Uuid>,
    pub status: String,
    pub project_manager_id: Option<Uuid>,
    pub start_date: Option<NaiveDate>,
    pub target_end_date: Option<NaiveDate>,
    pub actual_end_date: Option<NaiveDate>,
    pub budget_hours: Option<Decimal>,
    pub budget_amount: Option<Decimal>,
    /// Actual hours rolled up from approved time entries on this project
    /// (PMS-51 AC1). Derived on read; pair with `budget_hours` for
    /// budget-vs-actual. Zero when no approved time is logged.
    pub actual_hours: Decimal,
    /// Actual billed/billable amount from approved time entries on this
    /// project. Pair with `budget_amount`.
    pub actual_amount: Decimal,
    pub billing_method: String,
    pub hourly_rate: Option<Decimal>,
    pub is_billable: bool,
    /// PMS-345: per-project override of the tenant-wide standard due date
    /// offset in business days. `None` inherits the tenant
    /// `scheduling/default_due_business_days` setting; `Some(0)` disables the
    /// default for tasks created in this project.
    pub default_due_business_days: Option<i16>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateProjectRequest {
    #[validate(length(min = 1, max = 80))]
    pub name: String,
    pub description: Option<String>,
    pub project_number: Option<String>,
    pub company_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    #[serde(default = "default_client")]
    pub project_type: String,
    #[serde(default = "default_planning")]
    pub status: String,
    pub project_manager_id: Option<Uuid>,
    pub start_date: Option<NaiveDate>,
    pub target_end_date: Option<NaiveDate>,
    /// Settable on create for parity with edit (PMS-361). Normally left unset
    /// on a new project; an MSP backfilling a project that already finished
    /// can record the real end date in one submission instead of create-then-edit.
    pub actual_end_date: Option<NaiveDate>,
    #[serde(default, deserialize_with = "decimal_opt::deserialize")]
    #[validate(custom(function = crate::utils::validation::validate_budget_hours))]
    pub budget_hours: Option<Decimal>,
    #[serde(default, deserialize_with = "decimal_opt::deserialize")]
    #[validate(custom(function = crate::utils::validation::validate_budget_amount))]
    pub budget_amount: Option<Decimal>,
    #[serde(default = "default_tm")]
    pub billing_method: String,
    #[validate(custom(function = mokosh_types::validation::validate_rate))]
    pub hourly_rate: Option<Decimal>,
    #[serde(default = "default_true")]
    pub is_billable: bool,
    /// PMS-345: per-project override of the standard due date offset in
    /// business days (0..=365, 0 disables). `None` inherits the tenant
    /// `scheduling/default_due_business_days` setting.
    #[validate(range(min = 0, max = 365))]
    pub default_due_business_days: Option<i16>,
}

fn default_client() -> String {
    "client".into()
}
fn default_planning() -> String {
    "planning".into()
}
fn default_tm() -> String {
    "time_and_materials".into()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateProjectRequest {
    #[validate(length(min = 1, max = 80))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub project_manager_id: Option<Uuid>,
    pub start_date: Option<NaiveDate>,
    pub target_end_date: Option<NaiveDate>,
    pub actual_end_date: Option<NaiveDate>,
    #[serde(default, deserialize_with = "decimal_opt::deserialize")]
    #[validate(custom(function = crate::utils::validation::validate_budget_hours))]
    pub budget_hours: Option<Decimal>,
    #[serde(default, deserialize_with = "decimal_opt::deserialize")]
    #[validate(custom(function = crate::utils::validation::validate_budget_amount))]
    pub budget_amount: Option<Decimal>,
    pub billing_method: Option<String>,
    #[validate(custom(function = mokosh_types::validation::validate_rate))]
    pub hourly_rate: Option<Decimal>,
    pub is_billable: Option<bool>,
    /// PMS-345: per-project override of the standard due date offset in
    /// business days (0..=365, 0 disables). Omit to leave unchanged.
    #[validate(range(min = 0, max = 365))]
    pub default_due_business_days: Option<i16>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct ProjectFilter {
    pub company_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub status: Option<String>,
    pub project_manager_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectPhaseResponse {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: i32,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertProjectPhaseRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub sort_order: i32,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
    #[serde(default = "default_not_started")]
    pub status: String,
}

fn default_not_started() -> String {
    "not_started".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskStatusResponse {
    pub id: Uuid,
    pub name: String,
    pub color: String,
    pub is_completed: bool,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertTaskStatusRequest {
    #[validate(length(min = 1, max = 50))]
    pub name: String,
    #[validate(length(min = 1, max = 7))]
    pub color: String,
    #[serde(default)]
    pub is_completed: bool,
    #[serde(default)]
    pub sort_order: i32,
}

/// Wire shape for a `project_types` lookup row (PMS-322). `is_system` is
/// read-only; the API sets it only on the seeded client/internal rows and
/// refuses to delete a row that carries it.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectTypeResponse {
    pub id: Uuid,
    pub name: String,
    pub is_default: bool,
    pub is_active: bool,
    pub sort_order: i32,
    pub is_system: bool,
}

/// Create/update body for a `project_types` lookup row. `is_system` is not
/// settable from the wire.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertProjectTypeRequest {
    #[validate(length(min = 1, max = 50))]
    pub name: String,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskResponse {
    pub id: Uuid,
    pub project_id: Option<Uuid>,
    pub phase_id: Option<Uuid>,
    pub parent_task_id: Option<Uuid>,
    pub title: String,
    pub description: Option<String>,
    pub status_id: Uuid,
    pub priority: String,
    pub assigned_to_id: Option<Uuid>,
    pub estimated_hours: Option<Decimal>,
    /// Actual hours rolled up from approved time entries linked to this
    /// task (PMS-51 AC5). Derived on read, not settable directly.
    pub actual_hours: Option<Decimal>,
    /// Logged hours rolled up from every non-rejected time entry linked to
    /// this task (draft + pending + approved), in hours (PMS-329). Always
    /// `>= actual_hours`. Derived on read, not settable directly.
    pub logged_hours: Option<Decimal>,
    pub start_date: Option<NaiveDate>,
    pub due_date: Option<NaiveDate>,
    pub completed_at: Option<DateTime<Utc>>,
    pub sort_order: i32,
}

/// A task's `due_date` must be on or after its `start_date` (PMS-398):
/// inverted (negative-duration) ranges are rejected. Equality is allowed (a
/// single-day task is valid). A `None` on either side means "unbounded on that
/// end" and is always accepted. Shared by the create and update request
/// validators (and the update service path) so every entry point enforces the
/// same rule. Mirrors `appointment_range_ok` (PMS-343) and the contract date
/// range check (PMS-306).
pub(crate) fn task_dates_ok(start: Option<NaiveDate>, due: Option<NaiveDate>) -> bool {
    match (start, due) {
        (Some(start), Some(due)) => start <= due,
        _ => true,
    }
}

/// Cross-field check for `CreateTaskRequest`: an inverted start/due range is
/// rejected with a 422 at the request layer. The error is re-keyed onto
/// `due_date` so the SPA renders it inline against that field rather than as a
/// generic banner (PMS-364).
fn validate_create_task_dates(req: &CreateTaskRequest) -> Result<(), validator::ValidationError> {
    if !task_dates_ok(req.start_date, req.due_date) {
        return Err(crate::utils::validation::cross_field_error(
            "task_dates_inverted",
            "due_date",
            "Due date must be on or after the start date",
        ));
    }
    Ok(())
}

/// Cross-field check for `UpdateTaskRequest`. A partial PUT that supplies both
/// dates is validated the same way as a create; one-sided updates fall through
/// to the service layer, which combines the request values with the stored row.
fn validate_update_task_dates(req: &UpdateTaskRequest) -> Result<(), validator::ValidationError> {
    if !task_dates_ok(req.start_date, req.due_date) {
        return Err(crate::utils::validation::cross_field_error(
            "task_dates_inverted",
            "due_date",
            "Due date must be on or after the start date",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[validate(schema(function = validate_create_task_dates))]
pub struct CreateTaskRequest {
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    pub description: Option<String>,
    pub status_id: Uuid,
    pub phase_id: Option<Uuid>,
    pub parent_task_id: Option<Uuid>,
    #[serde(default = "default_medium")]
    pub priority: String,
    pub assigned_to_id: Option<Uuid>,
    #[validate(custom(function = mokosh_types::validation::validate_hours))]
    pub estimated_hours: Option<Decimal>,
    pub start_date: Option<NaiveDate>,
    pub due_date: Option<NaiveDate>,
    #[serde(default)]
    pub sort_order: i32,
}

fn default_medium() -> String {
    "medium".into()
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[validate(schema(function = validate_update_task_dates))]
pub struct UpdateTaskRequest {
    #[validate(length(min = 1, max = 255))]
    pub title: Option<String>,
    pub description: Option<String>,
    pub status_id: Option<Uuid>,
    pub phase_id: Option<Uuid>,
    pub priority: Option<String>,
    pub assigned_to_id: Option<Uuid>,
    #[validate(custom(function = mokosh_types::validation::validate_hours))]
    pub estimated_hours: Option<Decimal>,
    pub start_date: Option<NaiveDate>,
    pub due_date: Option<NaiveDate>,
    pub sort_order: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).expect("valid date")
    }

    #[test]
    fn task_dates_ok_both_none() {
        assert!(task_dates_ok(None, None));
    }

    #[test]
    fn task_dates_ok_only_start() {
        assert!(task_dates_ok(Some(d(2026, 6, 18)), None));
    }

    #[test]
    fn task_dates_ok_only_due() {
        assert!(task_dates_ok(None, Some(d(2026, 6, 18))));
    }

    #[test]
    fn task_dates_ok_equal() {
        assert!(task_dates_ok(Some(d(2026, 6, 18)), Some(d(2026, 6, 18))));
    }

    #[test]
    fn task_dates_ok_valid_ordered() {
        assert!(task_dates_ok(Some(d(2026, 6, 18)), Some(d(2026, 6, 20))));
    }

    #[test]
    fn task_dates_ok_inverted() {
        assert!(!task_dates_ok(Some(d(2026, 6, 20)), Some(d(2026, 6, 18))));
    }
}
