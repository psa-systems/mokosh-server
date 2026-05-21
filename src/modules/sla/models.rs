//! SLA DTOs.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct SlaPolicyResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub business_hours_id: Option<Uuid>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertSlaPolicyRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    pub business_hours_id: Option<Uuid>,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlaTargetResponse {
    pub id: Uuid,
    pub sla_policy_id: Uuid,
    pub priority_id: Uuid,
    pub first_response_hours: Option<Decimal>,
    pub resolution_hours: Option<Decimal>,
    pub operational_hours: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertSlaTargetRequest {
    pub priority_id: Uuid,
    pub first_response_hours: Option<Decimal>,
    pub resolution_hours: Option<Decimal>,
    /// "business_hours" | "24x7"
    #[serde(default = "default_24x7")]
    pub operational_hours: String,
}

fn default_24x7() -> String { "24x7".into() }

#[derive(Debug, Clone, Serialize)]
pub struct BusinessHoursResponse {
    pub id: Uuid,
    pub name: String,
    pub timezone: String,
    pub schedule: serde_json::Value,
    pub is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertBusinessHoursRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[serde(default = "default_utc")]
    pub timezone: String,
    /// Per-day windows, e.g.
    /// `{"mon": [{"start": "09:00", "end": "17:00"}], ...}`.
    #[serde(default)]
    pub schedule: serde_json::Value,
    #[serde(default)]
    pub is_default: bool,
}

fn default_utc() -> String { "UTC".into() }

#[derive(Debug, Clone, Serialize)]
pub struct HolidayCalendarResponse {
    pub id: Uuid,
    pub name: String,
    /// List of `{date, name}` entries.
    pub holidays: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertHolidayCalendarRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[serde(default)]
    pub holidays: serde_json::Value,
}
