//! RMM DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct RmmConnectionResponse {
    pub id: Uuid,
    pub name: String,
    pub provider: String,
    pub api_url: String,
    pub is_active: bool,
    pub sync_interval_minutes: i32,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub sync_status: String,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateRmmConnectionRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    /// "tactical_rmm" | "mesh_central" | "datto" | "connectwise" | "ninja_rmm"
    pub provider: String,
    #[validate(url)]
    pub api_url: String,
    pub api_key: String,
    pub api_secret: Option<String>,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default = "default_60")]
    pub sync_interval_minutes: i32,
}

fn default_60() -> i32 {
    60
}

/// PUT /api/v1/rmm/connections/{id}. Missing fields are left untouched
/// so an admin can flip `is_active` or `sync_interval_minutes` without
/// re-sending the credential (which would re-encrypt them under a
/// fresh nonce for no reason). `api_key` / `api_secret` are only
/// re-encrypted when explicitly supplied.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateRmmConnectionRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,
    #[validate(url)]
    pub api_url: Option<String>,
    pub api_key: Option<String>,
    pub api_secret: Option<String>,
    pub is_active: Option<bool>,
    pub sync_interval_minutes: Option<i32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RmmDeviceMappingResponse {
    pub id: Uuid,
    pub rmm_connection_id: Uuid,
    pub rmm_device_id: String,
    pub asset_id: Option<Uuid>,
    pub company_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub sync_status: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateRmmDeviceMappingRequest {
    pub rmm_connection_id: Uuid,
    #[validate(length(min = 1, max = 255))]
    pub rmm_device_id: String,
    pub asset_id: Option<Uuid>,
    pub company_id: Option<Uuid>,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RmmAlertRuleResponse {
    pub id: Uuid,
    pub rmm_connection_id: Uuid,
    pub name: String,
    pub alert_type: Option<String>,
    pub auto_create_ticket: bool,
    pub assign_to_id: Option<Uuid>,
    pub queue_id: Option<Uuid>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertRmmAlertRuleRequest {
    pub rmm_connection_id: Uuid,
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub alert_type: Option<String>,
    #[serde(default = "default_true")]
    pub auto_create_ticket: bool,
    pub assign_to_id: Option<Uuid>,
    pub queue_id: Option<Uuid>,
    #[serde(default)]
    pub ticket_template: serde_json::Value,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

/// Body for `POST /api/v1/rmm/alerts`. The RMM agent fires this with an
/// HMAC signature in the `X-Signature` header (HMAC-SHA256 of the raw
/// body using the connection's `api_secret`). Service layer verifies.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct IngestAlertRequest {
    pub rmm_connection_id: Uuid,
    pub rmm_device_id: String,
    /// Matched against `rmm_alert_rules.alert_type`.
    pub alert_type: String,
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    pub message: Option<String>,
    /// "low" | "medium" | "high" | "critical"
    pub severity: Option<String>,
}
