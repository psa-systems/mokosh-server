//! Notifications DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct NotificationChannelResponse {
    pub id: Uuid,
    pub channel_type: String,
    pub name: String,
    pub config: serde_json::Value, // decrypted
    pub is_active: bool,
    pub is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertNotificationChannelRequest {
    /// "email" | "sms" | "slack" | "teams" | "discord" | "google_chat"
    /// | "mattermost" | "in_app"
    pub channel_type: String,
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub config: serde_json::Value,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationTemplateResponse {
    pub id: Uuid,
    pub name: String,
    pub event_type: String,
    pub channel_type: String,
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertNotificationTemplateRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub event_type: String,
    pub channel_type: String,
    pub subject: Option<String>,
    #[validate(length(min = 1))]
    pub body_text: String,
    pub body_html: Option<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct UserNotificationPreferenceResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub event_type: String,
    pub channel_types: Vec<String>,
    pub is_enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertUserNotificationPreferenceRequest {
    pub event_type: String,
    pub channel_types: Vec<String>,
    #[serde(default = "default_true")]
    pub is_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationInboxItemResponse {
    pub id: Uuid,
    pub channel_type: String,
    pub subject: Option<String>,
    pub body: String,
    pub status: String,
    pub sent_at: Option<DateTime<Utc>>,
    pub read_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationRuleResponse {
    pub id: Uuid,
    pub name: String,
    pub event_type: String,
    pub conditions: serde_json::Value,
    pub channels: Vec<String>,
    pub recipients: serde_json::Value,
    pub template_id: Option<Uuid>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertNotificationRuleRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub event_type: String,
    #[serde(default)]
    pub conditions: serde_json::Value,
    pub channels: Vec<String>,
    pub recipients: serde_json::Value,
    pub template_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

/// Body for the manual dispatch endpoint (`POST /notifications/dispatch`):
/// fire a rule's recipients for an event ad-hoc, e.g. from an admin
/// "test rule" button. Schedulers and the rules engine eventually call
/// `NotificationsService::dispatch` directly.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct DispatchNotificationRequest {
    pub event_type: String,
    #[serde(default)]
    pub context: serde_json::Value,
}
