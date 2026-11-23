//! Notifications DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};

/// Channel types the worker has a transport for; anything else fails permanently at send time.
const SUPPORTED_CHANNEL_TYPES: [&str; 2] = ["in_app", "email"];

const CHANNEL_TYPE_MESSAGE: &str = "channel_type must be one of 'in_app' or 'email'";

pub fn validate_channel_type(value: &str) -> Result<(), ValidationError> {
    if SUPPORTED_CHANNEL_TYPES.contains(&value) {
        Ok(())
    } else {
        Err(ValidationError::new("unsupported_channel_type")
            .with_message(CHANNEL_TYPE_MESSAGE.into()))
    }
}

pub fn validate_channel_types_vec(values: &[String]) -> Result<(), ValidationError> {
    values.iter().try_for_each(|v| validate_channel_type(v))
}

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
    #[validate(custom(function = "validate_channel_type"))]
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
    #[validate(custom(function = "validate_channel_type"))]
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
    #[validate(custom(function = "validate_channel_types_vec"))]
    pub channel_types: Vec<String>,
    // SPEC-7.587: is_enabled defaults to true when omitted from the request JSON.
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
    /// The row the notification is about (`ticket`, `invoice`, ...) and
    /// its id, when the dispatch context named one (migration 150,
    /// written since PMS-1083), so an inbox can deep-link.
    pub entity_type: Option<String>,
    pub entity_id: Option<Uuid>,
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
    /// Required (PMS-701): a rule with no template has nothing to render,
    /// and `dispatch` skips it instead of mailing a fallback body.
    #[validate(required)]
    pub template_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

/// Body for the manual dispatch endpoint (`POST /notifications/dispatch`):
/// fire a rule's recipients for an event ad-hoc, e.g. from an admin
/// "test rule" button. Schedulers and the rules engine eventually call
/// `NotificationsService::dispatch` directly.
///
/// `POST /notifications/preview` (PMS-808) takes the same body: the
/// preview answers "what would this dispatch say?", so asking for it
/// with a different shape would only invite the two to drift.
// SPEC-7.629: DispatchNotificationRequest derives Validate but declares no field-level #[validate(...)] attributes, so req.validate()? at both the dispatch and preview routes is a structural no-op.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct DispatchNotificationRequest {
    pub event_type: String,
    #[serde(default)]
    pub context: serde_json::Value,
}

/// One message `dispatch` would queue, as returned by
/// `POST /notifications/preview` (PMS-808): one entry per (rule,
/// channel) pair that would fire, in dispatch order.
///
/// `unresolved` names the `{{key}}` placeholders the context did not
/// carry. Those stay literal in `subject` / `body_text` / `body_html`
/// rather than being filled with a sample value, because they are the
/// send-time values (a minted token and its link) that the preview
/// deliberately does not create.
// SPEC-7.582: unresolved names the exact {{key}} placeholders that did not resolve; those keys stay literal in subject/body_text/body_html rather than being fabricated as a sample send-time value.
#[derive(Debug, Clone, Serialize)]
pub struct NotificationPreviewResponse {
    pub rule_name: String,
    pub channel: String,
    pub recipients: Vec<String>,
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub unresolved: Vec<String>,
}

#[cfg(test)]
mod channel_type_tests {
    use super::*;

    #[test]
    fn supported_channel_types_pass() {
        assert!(validate_channel_type("in_app").is_ok());
        assert!(validate_channel_type("email").is_ok());
    }

    #[test]
    fn unsupported_channel_types_fail_with_message() {
        for v in ["sms", "slack", "teams", "", "random"] {
            let err = validate_channel_type(v).expect_err(v);
            assert_eq!(err.message.as_deref(), Some(CHANNEL_TYPE_MESSAGE));
        }
    }

    #[test]
    fn vec_with_one_bad_element_fails() {
        let ok = vec!["in_app".to_string(), "email".to_string()];
        assert!(validate_channel_types_vec(&ok).is_ok());
        let bad = vec!["in_app".to_string(), "sms".to_string()];
        assert!(validate_channel_types_vec(&bad).is_err());
    }

    #[test]
    fn channel_request_validate_rejects_bad_type() {
        let req = UpsertNotificationChannelRequest {
            channel_type: "sms".into(),
            name: "x".into(),
            config: serde_json::json!({}),
            is_active: true,
            is_default: false,
        };
        let errors = req.validate().expect_err("sms must fail");
        assert!(errors.field_errors().contains_key("channel_type"));
    }
}
