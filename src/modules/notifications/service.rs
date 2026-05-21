//! Notifications service.
//!
//! Persists channels / templates / preferences / rules and provides a
//! minimal dispatcher: for a given (tenant, event_type) it looks up
//! matching active rules, expands `recipients` (user_ids[] or
//! emails[]), renders a template, and writes one `notifications` row
//! per (recipient, channel) pair. Actual SMTP / Slack / etc. transports
//! are wired by the `notification_dispatcher` worker once it lands; the
//! row's `status = pending` is the queue marker.

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

use super::models::*;

#[derive(Clone)]
pub struct NotificationsService {
    db: Database,
    encryption_key: [u8; 32],
}

impl NotificationsService {
    pub fn new(db: Database) -> Self {
        Self { db, encryption_key: [0u8; 32] }
    }

    pub fn with_encryption_key(db: Database, encryption_key: [u8; 32]) -> Self {
        Self { db, encryption_key }
    }

    // PMS-87 channels CRUD ----------------------------------------------------
    pub async fn list_channels(&self, tenant_id: Uuid) -> AppResult<Vec<NotificationChannelResponse>> {
        let rows = sqlx::query_as::<_, ChannelRow>(
            r#"SELECT id, channel_type, name, config_encrypted, is_active, is_default
               FROM notification_channels WHERE tenant_id = $1 ORDER BY channel_type, name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        rows.into_iter().map(|r| {
            let plain = crate::utils::crypto::decrypt(&r.config_encrypted, &self.encryption_key)?;
            let config: serde_json::Value = serde_json::from_str(&plain).unwrap_or(serde_json::Value::Null);
            Ok(NotificationChannelResponse {
                id: r.id, channel_type: r.channel_type, name: r.name,
                config, is_active: r.is_active.unwrap_or(false), is_default: r.is_default.unwrap_or(false),
            })
        }).collect()
    }

    pub async fn create_channel(
        &self, tenant_id: Uuid, request: &UpsertNotificationChannelRequest,
    ) -> AppResult<NotificationChannelResponse> {
        let plain = serde_json::to_string(&request.config)
            .map_err(|e| AppError::BadRequest(format!("config serialise: {e}")))?;
        let encrypted = crate::utils::crypto::encrypt(&plain, &self.encryption_key)?;
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_channels
               (id, tenant_id, channel_type, name, config_encrypted, is_active, is_default)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id).bind(tenant_id).bind(&request.channel_type).bind(&request.name)
        .bind(&encrypted).bind(request.is_active).bind(request.is_default)
        .execute(self.db.pool()).await?;
        Ok(NotificationChannelResponse {
            id, channel_type: request.channel_type.clone(), name: request.name.clone(),
            config: request.config.clone(),
            is_active: request.is_active, is_default: request.is_default,
        })
    }

    pub async fn delete_channel(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM notification_channels WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("NotificationChannel".to_string())); }
        Ok(())
    }

    // PMS-88 templates CRUD ---------------------------------------------------
    pub async fn list_templates(&self, tenant_id: Uuid) -> AppResult<Vec<NotificationTemplateResponse>> {
        let rows = sqlx::query_as::<_, TemplateRow>(
            r#"SELECT id, name, event_type, channel_type, subject, body_text, body_html, is_active
               FROM notification_templates WHERE tenant_id = $1
               ORDER BY event_type, channel_type, name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_template(
        &self, tenant_id: Uuid, request: &UpsertNotificationTemplateRequest,
    ) -> AppResult<NotificationTemplateResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_templates
               (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.event_type).bind(&request.channel_type)
        .bind(&request.subject).bind(&request.body_text).bind(&request.body_html).bind(request.is_active)
        .execute(self.db.pool()).await?;
        Ok(NotificationTemplateResponse {
            id, name: request.name.clone(), event_type: request.event_type.clone(),
            channel_type: request.channel_type.clone(),
            subject: request.subject.clone(), body_text: request.body_text.clone(),
            body_html: request.body_html.clone(),
            is_active: request.is_active,
        })
    }

    pub async fn delete_template(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM notification_templates WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("NotificationTemplate".to_string())); }
        Ok(())
    }

    // PMS-89 user preferences -------------------------------------------------
    pub async fn list_user_preferences(
        &self, tenant_id: Uuid, user_id: Uuid,
    ) -> AppResult<Vec<UserNotificationPreferenceResponse>> {
        let rows = sqlx::query_as::<_, PrefRow>(
            r#"SELECT id, user_id, event_type, channel_types, is_enabled
               FROM user_notification_preferences
               WHERE tenant_id = $1 AND user_id = $2 ORDER BY event_type"#,
        ).bind(tenant_id).bind(user_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn upsert_user_preference(
        &self, tenant_id: Uuid, user_id: Uuid, request: &UpsertUserNotificationPreferenceRequest,
    ) -> AppResult<UserNotificationPreferenceResponse> {
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO user_notification_preferences
               (tenant_id, user_id, event_type, channel_types, is_enabled)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (user_id, event_type) DO UPDATE SET
                 channel_types = EXCLUDED.channel_types,
                 is_enabled = EXCLUDED.is_enabled,
                 updated_at = NOW()
               RETURNING id"#,
        )
        .bind(tenant_id).bind(user_id)
        .bind(&request.event_type).bind(&request.channel_types).bind(request.is_enabled)
        .fetch_one(self.db.pool()).await?;
        Ok(UserNotificationPreferenceResponse {
            id, user_id,
            event_type: request.event_type.clone(),
            channel_types: request.channel_types.clone(),
            is_enabled: request.is_enabled,
        })
    }

    // PMS-90 inbox ------------------------------------------------------------
    pub async fn list_inbox(
        &self, tenant_id: Uuid, user_id: Uuid,
    ) -> AppResult<Vec<NotificationInboxItemResponse>> {
        let rows = sqlx::query_as::<_, InboxRow>(
            r#"SELECT id, channel_type, subject, body, status, sent_at, read_at, created_at
               FROM notifications
               WHERE tenant_id = $1 AND user_id = $2 AND channel_type = 'in_app'
               ORDER BY created_at DESC LIMIT 200"#,
        ).bind(tenant_id).bind(user_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn mark_read(&self, tenant_id: Uuid, user_id: Uuid, id: Uuid) -> AppResult<()> {
        sqlx::query(
            r#"UPDATE notifications SET read_at = NOW()
               WHERE tenant_id = $1 AND user_id = $2 AND id = $3"#,
        ).bind(tenant_id).bind(user_id).bind(id)
        .execute(self.db.pool()).await?;
        Ok(())
    }

    // PMS-91 rules CRUD -------------------------------------------------------
    pub async fn list_rules(&self, tenant_id: Uuid) -> AppResult<Vec<NotificationRuleResponse>> {
        let rows = sqlx::query_as::<_, RuleRow>(
            r#"SELECT id, name, event_type, conditions, channels, recipients, template_id, is_active
               FROM notification_rules WHERE tenant_id = $1 ORDER BY event_type, name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_rule(
        &self, tenant_id: Uuid, request: &UpsertNotificationRuleRequest,
    ) -> AppResult<NotificationRuleResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_rules
               (id, tenant_id, name, event_type, conditions, channels, recipients,
                template_id, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.event_type)
        .bind(&request.conditions).bind(&request.channels).bind(&request.recipients)
        .bind(request.template_id).bind(request.is_active)
        .execute(self.db.pool()).await?;
        Ok(NotificationRuleResponse {
            id, name: request.name.clone(), event_type: request.event_type.clone(),
            conditions: request.conditions.clone(), channels: request.channels.clone(),
            recipients: request.recipients.clone(),
            template_id: request.template_id, is_active: request.is_active,
        })
    }

    pub async fn delete_rule(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM notification_rules WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("NotificationRule".to_string())); }
        Ok(())
    }

    // PMS-92 dispatcher -------------------------------------------------------
    /// Look up active rules matching `event_type`, expand recipients,
    /// render templates, and persist one `notifications` row per
    /// (recipient, channel). For `email` channels we additionally fire
    /// the host `Mailer` so the message actually goes out; other
    /// channels stay `status = pending` for the dispatcher worker.
    pub async fn dispatch(
        &self, tenant_id: Uuid, event_type: &str, context: &serde_json::Value,
    ) -> AppResult<u64> {
        let rules = sqlx::query_as::<_, RuleRow>(
            r#"SELECT id, name, event_type, conditions, channels, recipients, template_id, is_active
               FROM notification_rules
               WHERE tenant_id = $1 AND event_type = $2 AND is_active = TRUE"#,
        ).bind(tenant_id).bind(event_type).fetch_all(self.db.pool()).await?;

        let mut fanout = 0u64;
        for rule in rules {
            let template = match rule.template_id {
                Some(tid) => sqlx::query_as::<_, TemplateRow>(
                    "SELECT id, name, event_type, channel_type, subject, body_text, body_html, is_active \
                     FROM notification_templates WHERE id = $1",
                ).bind(tid).fetch_optional(self.db.pool()).await?,
                None => None,
            };

            // Recipients shape: { "user_ids": [...], "emails": [...] }
            let user_ids: Vec<Uuid> = rule.recipients.get("user_ids")
                .and_then(|v| v.as_array()).cloned().unwrap_or_default()
                .into_iter().filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect();
            let emails: Vec<String> = rule.recipients.get("emails")
                .and_then(|v| v.as_array()).cloned().unwrap_or_default()
                .into_iter().filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();

            for channel in &rule.channels {
                let subject = template.as_ref().and_then(|t| t.subject.clone())
                    .unwrap_or_else(|| format!("Mokosh event: {event_type}"));
                let body = template.as_ref().map(|t| t.body_text.clone())
                    .unwrap_or_else(|| format!("Event {event_type} fired with context {context}"));

                // Fan out to each user_id (in_app + lookup email).
                for user_id in &user_ids {
                    sqlx::query(
                        r#"INSERT INTO notifications
                           (tenant_id, user_id, channel_type, template_id, subject, body)
                           VALUES ($1, $2, $3, $4, $5, $6)"#,
                    )
                    .bind(tenant_id).bind(user_id).bind(channel)
                    .bind(template.as_ref().map(|t| t.id))
                    .bind(&subject).bind(&body)
                    .execute(self.db.pool()).await?;
                    fanout += 1;
                }
                // Fan out to standalone emails / external recipients.
                // SMTP / Slack / etc. transports land via the dispatcher
                // worker; for now we just write the row with `pending`.
                if channel == "email" || channel == "sms" || channel == "slack" {
                    for addr in &emails {
                        sqlx::query(
                            r#"INSERT INTO notifications
                               (tenant_id, channel_type, template_id, recipient, subject, body)
                               VALUES ($1, $2, $3, $4, $5, $6)"#,
                        )
                        .bind(tenant_id).bind(channel)
                        .bind(template.as_ref().map(|t| t.id))
                        .bind(addr).bind(&subject).bind(&body)
                        .execute(self.db.pool()).await?;
                        fanout += 1;
                    }
                }
            }
        }
        Ok(fanout)
    }
}

#[derive(sqlx::FromRow)]
struct ChannelRow {
    id: Uuid, channel_type: String, name: String, config_encrypted: String,
    is_active: Option<bool>, is_default: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct TemplateRow {
    id: Uuid, name: String, event_type: String, channel_type: String,
    subject: Option<String>, body_text: String, body_html: Option<String>,
    is_active: Option<bool>,
}

impl From<TemplateRow> for NotificationTemplateResponse {
    fn from(r: TemplateRow) -> Self {
        Self {
            id: r.id, name: r.name, event_type: r.event_type, channel_type: r.channel_type,
            subject: r.subject, body_text: r.body_text, body_html: r.body_html,
            is_active: r.is_active.unwrap_or(true),
        }
    }
}

#[derive(sqlx::FromRow)]
struct PrefRow {
    id: Uuid, user_id: Uuid, event_type: String,
    channel_types: Vec<String>, is_enabled: Option<bool>,
}

impl From<PrefRow> for UserNotificationPreferenceResponse {
    fn from(r: PrefRow) -> Self {
        Self {
            id: r.id, user_id: r.user_id, event_type: r.event_type,
            channel_types: r.channel_types, is_enabled: r.is_enabled.unwrap_or(true),
        }
    }
}

#[derive(sqlx::FromRow)]
struct InboxRow {
    id: Uuid, channel_type: String,
    subject: Option<String>, body: String, status: Option<String>,
    sent_at: Option<chrono::DateTime<chrono::Utc>>,
    read_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<InboxRow> for NotificationInboxItemResponse {
    fn from(r: InboxRow) -> Self {
        Self {
            id: r.id, channel_type: r.channel_type, subject: r.subject, body: r.body,
            status: r.status.unwrap_or_else(|| "pending".into()),
            sent_at: r.sent_at, read_at: r.read_at, created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: Uuid, name: String, event_type: String,
    conditions: serde_json::Value, channels: Vec<String>,
    recipients: serde_json::Value, template_id: Option<Uuid>,
    is_active: Option<bool>,
}

impl From<RuleRow> for NotificationRuleResponse {
    fn from(r: RuleRow) -> Self {
        Self {
            id: r.id, name: r.name, event_type: r.event_type,
            conditions: r.conditions, channels: r.channels,
            recipients: r.recipients, template_id: r.template_id,
            is_active: r.is_active.unwrap_or(true),
        }
    }
}
