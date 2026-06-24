//! PMS-457: saved-report DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct SavedReportResponse {
    pub id: Uuid,
    pub created_by_id: Uuid,
    /// Resolved author display name (LEFT JOIN). `None` if the user
    /// was deleted; the SPA renders that as "(deleted user)".
    pub created_by_name: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub entity_type: String,
    pub filters: serde_json::Value,
    pub columns: serde_json::Value,
    pub group_by: serde_json::Value,
    pub sort: serde_json::Value,
    pub is_shared: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateSavedReportRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    pub description: Option<String>,
    /// Free-text discriminator the Phase 2 runtime maps to a
    /// service (tickets / time_entries / invoices / ...). Phase 1
    /// stores opaquely; the SPA's report-builder UI guards the
    /// shape.
    #[validate(length(min = 1, max = 50))]
    pub entity_type: String,
    #[serde(default = "default_empty_object")]
    pub filters: serde_json::Value,
    #[serde(default = "default_empty_array")]
    pub columns: serde_json::Value,
    #[serde(default = "default_empty_array")]
    pub group_by: serde_json::Value,
    #[serde(default = "default_empty_array")]
    pub sort: serde_json::Value,
    #[serde(default)]
    pub is_shared: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateSavedReportRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub filters: Option<serde_json::Value>,
    pub columns: Option<serde_json::Value>,
    pub group_by: Option<serde_json::Value>,
    pub sort: Option<serde_json::Value>,
    pub is_shared: Option<bool>,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}

fn default_empty_array() -> serde_json::Value {
    serde_json::json!([])
}

/// PMS-478: one scheduled delivery for a saved report. The owner
/// (`user_id`) is the visibility identity for the execute call (so a
/// schedule against a private report only the owner can see does NOT
/// silently grant the worker more access than the SPA would), and
/// the default recipient when `recipient_email` is null.
#[derive(Debug, Clone, Serialize)]
pub struct ScheduledReportResponse {
    pub id: Uuid,
    pub saved_report_id: Uuid,
    pub user_id: Uuid,
    pub cron_expr: String,
    pub channel: String,
    pub format: String,
    pub recipient_email: Option<String>,
    pub is_active: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateScheduledReportRequest {
    /// Standard cron expression. Validated with
    /// `utils::validation::validate_cron` (cron crate, 6-field form
    /// with seconds).
    #[validate(length(min = 1, max = 100), custom(function = crate::utils::validation::validate_cron))]
    pub cron_expr: String,
    /// Override the owning user's email as the delivery target.
    /// Useful for "schedule a weekly report for the CFO without
    /// adding them as a mokosh user" cases. Null = deliver to the
    /// owner's `users.email`.
    #[validate(email, length(max = 255))]
    pub recipient_email: Option<String>,
    #[serde(default = "default_true_active")]
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateScheduledReportRequest {
    #[validate(length(min = 1, max = 100), custom(function = crate::utils::validation::validate_cron))]
    pub cron_expr: Option<String>,
    #[validate(email, length(max = 255))]
    pub recipient_email: Option<String>,
    pub is_active: Option<bool>,
}

fn default_true_active() -> bool {
    true
}
