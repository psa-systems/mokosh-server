//! Projects + tasks DTOs.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct ProjectResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub project_number: Option<String>,
    pub company_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    pub project_type: String,
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
    #[validate(length(min = 1, max = 255))]
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
    pub budget_hours: Option<Decimal>,
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
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub project_manager_id: Option<Uuid>,
    pub start_date: Option<NaiveDate>,
    pub target_end_date: Option<NaiveDate>,
    pub actual_end_date: Option<NaiveDate>,
    pub budget_hours: Option<Decimal>,
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
