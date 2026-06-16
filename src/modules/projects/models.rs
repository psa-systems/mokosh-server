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
    #[serde(default, deserialize_with = "decimal_opt::deserialize")]
    #[validate(custom(function = crate::utils::validation::validate_budget_hours))]
    pub budget_hours: Option<Decimal>,
    #[serde(default, deserialize_with = "decimal_opt::deserialize")]
    #[validate(custom(function = crate::utils::validation::validate_budget_amount))]
    pub budget_amount: Option<Decimal>,
    #[serde(default = "default_tm")]
    pub billing_method: String,
    pub hourly_rate: Option<Decimal>,
    #[serde(default = "default_true")]
    pub is_billable: bool,
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
    pub hourly_rate: Option<Decimal>,
    pub is_billable: Option<bool>,
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

#[derive(Debug, Clone, Deserialize, Validate)]
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
pub struct UpdateTaskRequest {
    #[validate(length(min = 1, max = 255))]
    pub title: Option<String>,
    pub description: Option<String>,
    pub status_id: Option<Uuid>,
    pub phase_id: Option<Uuid>,
    pub priority: Option<String>,
    pub assigned_to_id: Option<Uuid>,
    pub estimated_hours: Option<Decimal>,
    pub start_date: Option<NaiveDate>,
    pub due_date: Option<NaiveDate>,
    pub sort_order: Option<i32>,
}
