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
    /// Build a NotificationsService wired to the per-deployment data
    /// encryption key. `notification_channels.config_encrypted` is
    /// AES-256-GCM ciphertext under this key, so swapping the key
    /// invalidates every existing channel config; rotate via the
    /// standard envelope flow, not by passing a different key here.
    ///
    /// There is no zero-key constructor on purpose: a previous version
    /// of this service silently fell back to `[0u8; 32]`, which made
    /// the at-rest encryption a no-op for any caller that forgot to
    /// pass the key (see PMS-92). Forcing the key through this
    /// constructor makes that mistake impossible.
    pub fn with_encryption_key(db: Database, encryption_key: [u8; 32]) -> Self {
        Self { db, encryption_key }
    }

    // PMS-87 channels CRUD ----------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_channels(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Vec<NotificationChannelResponse>> {
        let rows = sqlx::query_as::<_, ChannelRow>(
            r#"SELECT id, channel_type, name, config_encrypted, is_active, is_default
               FROM notification_channels WHERE tenant_id = $1 ORDER BY channel_type, name"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        rows.into_iter()
            .map(|r| {
                let plain =
                    crate::utils::crypto::decrypt(&r.config_encrypted, &self.encryption_key)?;
                let config: serde_json::Value =
                    serde_json::from_str(&plain).unwrap_or(serde_json::Value::Null);
                Ok(NotificationChannelResponse {
                    id: r.id,
                    channel_type: r.channel_type,
                    name: r.name,
                    config,
                    is_active: r.is_active.unwrap_or(false),
                    is_default: r.is_default.unwrap_or(false),
                })
            })
            .collect()
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_channel(
        &self,
        tenant_id: Uuid,
        request: &UpsertNotificationChannelRequest,
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
        .bind(id)
        .bind(tenant_id)
        .bind(&request.channel_type)
        .bind(&request.name)
        .bind(&encrypted)
        .bind(request.is_active)
        .bind(request.is_default)
        .execute(self.db.pool())
        .await?;
        Ok(NotificationChannelResponse {
            id,
            channel_type: request.channel_type.clone(),
            name: request.name.clone(),
            config: request.config.clone(),
            is_active: request.is_active,
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_channel(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM notification_channels WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("NotificationChannel".to_string()));
        }
        Ok(())
    }

    // PMS-88 templates CRUD ---------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_templates(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Vec<NotificationTemplateResponse>> {
        let rows = sqlx::query_as::<_, TemplateRow>(
            r#"SELECT id, name, event_type, channel_type, subject, body_text, body_html, is_active
               FROM notification_templates WHERE tenant_id = $1
               ORDER BY event_type, channel_type, name"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_template(
        &self,
        tenant_id: Uuid,
        request: &UpsertNotificationTemplateRequest,
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
            id,
            name: request.name.clone(),
            event_type: request.event_type.clone(),
            channel_type: request.channel_type.clone(),
            subject: request.subject.clone(),
            body_text: request.body_text.clone(),
            body_html: request.body_html.clone(),
            is_active: request.is_active,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_template(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM notification_templates WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("NotificationTemplate".to_string()));
        }
        Ok(())
    }

    // PMS-89 user preferences -------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_user_preferences(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<UserNotificationPreferenceResponse>> {
        let rows = sqlx::query_as::<_, PrefRow>(
            r#"SELECT id, user_id, event_type, channel_types, is_enabled
               FROM user_notification_preferences
               WHERE tenant_id = $1 AND user_id = $2 ORDER BY event_type"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_user_preference(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: &UpsertUserNotificationPreferenceRequest,
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
        .bind(tenant_id)
        .bind(user_id)
        .bind(&request.event_type)
        .bind(&request.channel_types)
        .bind(request.is_enabled)
        .fetch_one(self.db.pool())
        .await?;
        Ok(UserNotificationPreferenceResponse {
            id,
            user_id,
            event_type: request.event_type.clone(),
            channel_types: request.channel_types.clone(),
            is_enabled: request.is_enabled,
        })
    }

    // PMS-90 inbox ------------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_inbox(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<NotificationInboxItemResponse>> {
        let rows = sqlx::query_as::<_, InboxRow>(
            r#"SELECT id, channel_type, subject, body, status, sent_at, read_at, created_at
               FROM notifications
               WHERE tenant_id = $1 AND user_id = $2 AND channel_type = 'in_app'
               ORDER BY created_at DESC LIMIT 200"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn mark_read(&self, tenant_id: Uuid, user_id: Uuid, id: Uuid) -> AppResult<()> {
        sqlx::query(
            r#"UPDATE notifications SET read_at = NOW()
               WHERE tenant_id = $1 AND user_id = $2 AND id = $3"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(id)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    // PMS-91 rules CRUD -------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_rules(&self, tenant_id: Uuid) -> AppResult<Vec<NotificationRuleResponse>> {
        let rows = sqlx::query_as::<_, RuleRow>(
            r#"SELECT id, name, event_type, conditions, channels, recipients, template_id, is_active
               FROM notification_rules WHERE tenant_id = $1 ORDER BY event_type, name"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_rule(
        &self,
        tenant_id: Uuid,
        request: &UpsertNotificationRuleRequest,
    ) -> AppResult<NotificationRuleResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO notification_rules
               (id, tenant_id, name, event_type, conditions, channels, recipients,
                template_id, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.event_type)
        .bind(&request.conditions)
        .bind(&request.channels)
        .bind(&request.recipients)
        .bind(request.template_id)
        .bind(request.is_active)
        .execute(self.db.pool())
        .await?;
        Ok(NotificationRuleResponse {
            id,
            name: request.name.clone(),
            event_type: request.event_type.clone(),
            conditions: request.conditions.clone(),
            channels: request.channels.clone(),
            recipients: request.recipients.clone(),
            template_id: request.template_id,
            is_active: request.is_active,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_rule(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM notification_rules WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("NotificationRule".to_string()));
        }
        Ok(())
    }

    // PMS-92 dispatcher -------------------------------------------------------
    /// Look up active rules matching `event_type`, expand recipients
    /// (rule-defined + caller-supplied via context), render the template
    /// with `{{key}}` placeholders pulled from `context`, and persist
    /// one `notifications` row per (recipient, channel) with explicit
    /// `status = 'pending'`. The actual transport (SMTP, in-app flip,
    /// chat stubs) runs in the dispatcher worker; rows are the queue.
    ///
    /// Caller-supplied recipients are taken from these context keys (in
    /// addition to whatever the rule lists, with de-dup):
    ///   * `recipient_user_id`  - single UUID, fan-out as a user row
    ///   * `recipient_email`    - single string, fan-out as a recipient-only row
    ///
    /// Transactional events (password reset, welcome, ticket note) keep
    /// their rule.recipients empty and pass the user via context, so the
    /// rule is reusable across tenants without rewriting recipient lists.
    ///
    /// `user_notification_preferences` is consulted per (user_id,
    /// event_type, channel_type). If the user has an explicit row whose
    /// `is_enabled = false` OR whose `channel_types` does not include
    /// the channel, that row is skipped. Absent preferences = send (the
    /// project default).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn dispatch(
        &self,
        tenant_id: Uuid,
        event_type: &str,
        context: &serde_json::Value,
    ) -> AppResult<u64> {
        let rules = sqlx::query_as::<_, RuleRow>(
            r#"SELECT id, name, event_type, conditions, channels, recipients, template_id, is_active
               FROM notification_rules
               WHERE tenant_id = $1 AND event_type = $2 AND is_active = TRUE"#,
        )
        .bind(tenant_id)
        .bind(event_type)
        .fetch_all(self.db.pool())
        .await?;

        let ctx_user_id: Option<Uuid> = context
            .get("recipient_user_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());
        let ctx_email: Option<String> = context
            .get("recipient_email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut fanout = 0u64;
        for rule in rules {
            let template = match rule.template_id {
                Some(tid) => sqlx::query_as::<_, TemplateRow>(
                    "SELECT id, name, event_type, channel_type, subject, body_text, body_html, is_active \
                     FROM notification_templates WHERE id = $1",
                ).bind(tid).fetch_optional(self.db.pool()).await?,
                None => None,
            };

            // Merge rule.recipients with caller-supplied context recipients.
            let mut user_ids: Vec<Uuid> = rule
                .recipients
                .get("user_ids")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect();
            if let Some(uid) = ctx_user_id {
                if !user_ids.contains(&uid) {
                    user_ids.push(uid);
                }
            }

            let mut emails: Vec<String> = rule
                .recipients
                .get("emails")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if let Some(addr) = ctx_email.as_ref() {
                if !emails.iter().any(|e| e == addr) {
                    emails.push(addr.clone());
                }
            }

            for channel in &rule.channels {
                let raw_subject = template
                    .as_ref()
                    .and_then(|t| t.subject.clone())
                    .unwrap_or_else(|| format!("Mokosh event: {event_type}"));
                let raw_body = template
                    .as_ref()
                    .map(|t| t.body_text.clone())
                    .unwrap_or_else(|| format!("Event {event_type} fired with context {context}"));
                let subject = render_template(&raw_subject, context);
                let body = render_template(&raw_body, context);

                // Fan out to each user_id, honoring user preferences for
                // this (event_type, channel) pair.
                for user_id in &user_ids {
                    if !self
                        .user_accepts_channel(tenant_id, *user_id, event_type, channel)
                        .await?
                    {
                        continue;
                    }
                    sqlx::query(
                        r#"INSERT INTO notifications
                           (tenant_id, user_id, channel_type, template_id, subject, body, status)
                           VALUES ($1, $2, $3, $4, $5, $6, 'pending')"#,
                    )
                    .bind(tenant_id)
                    .bind(user_id)
                    .bind(channel)
                    .bind(template.as_ref().map(|t| t.id))
                    .bind(&subject)
                    .bind(&body)
                    .execute(self.db.pool())
                    .await?;
                    fanout += 1;
                }
                // Fan out to standalone email-style recipients (no user
                // row, no preferences to consult). in_app rows must
                // always belong to a user, so skip standalone recipients
                // on that channel.
                if channel != "in_app" {
                    for addr in &emails {
                        sqlx::query(
                            r#"INSERT INTO notifications
                               (tenant_id, channel_type, template_id, recipient, subject, body, status)
                               VALUES ($1, $2, $3, $4, $5, $6, 'pending')"#,
                        )
                        .bind(tenant_id)
                        .bind(channel)
                        .bind(template.as_ref().map(|t| t.id))
                        .bind(addr)
                        .bind(&subject)
                        .bind(&body)
                        .execute(self.db.pool())
                        .await?;
                        fanout += 1;
                    }
                }
            }
        }
        Ok(fanout)
    }

    /// Return true if `user_id` should receive `channel` for
    /// `event_type`. Absent prefs row = accept (project default). Row
    /// with `is_enabled = false` = reject. Row with `is_enabled = true`
    /// = accept only if `channel_types` contains the channel.
    async fn user_accepts_channel(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        event_type: &str,
        channel: &str,
    ) -> AppResult<bool> {
        let row: Option<(Option<bool>, Vec<String>)> = sqlx::query_as(
            r#"SELECT is_enabled, channel_types
               FROM user_notification_preferences
               WHERE tenant_id = $1 AND user_id = $2 AND event_type = $3"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(event_type)
        .fetch_optional(self.db.pool())
        .await?;

        match row {
            None => Ok(true),
            Some((enabled, channels)) => {
                if !enabled.unwrap_or(true) {
                    return Ok(false);
                }
                Ok(channels.iter().any(|c| c == channel))
            }
        }
    }
}

/// Minimal `{{key}}` substitution. Keys are resolved against the
/// top-level fields of `context`; missing keys leave the placeholder
/// untouched so an operator can see what was expected at delivery time.
/// String values render verbatim; other JSON values render as their
/// `Display` representation.
pub fn render_template(input: &str, context: &serde_json::Value) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        rest = &rest[open + 2..];
        let Some(close) = rest.find("}}") else {
            out.push_str("{{");
            out.push_str(rest);
            return out;
        };
        let key = rest[..close].trim();
        match context.get(key) {
            Some(serde_json::Value::String(s)) => out.push_str(s),
            Some(v) => out.push_str(&v.to_string()),
            None => {
                out.push_str("{{");
                out.push_str(&rest[..close]);
                out.push_str("}}");
            }
        }
        rest = &rest[close + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::render_template;
    use serde_json::json;

    #[test]
    fn render_substitutes_string_keys() {
        let out = render_template(
            "Hi {{name}}, see {{link}}",
            &json!({"name": "Pat", "link": "https://x"}),
        );
        assert_eq!(out, "Hi Pat, see https://x");
    }

    #[test]
    fn render_leaves_missing_keys_intact() {
        let out = render_template("Hello {{absent}}", &json!({}));
        assert_eq!(out, "Hello {{absent}}");
    }

    #[test]
    fn render_handles_non_string_values() {
        let out = render_template("count={{n}}", &json!({"n": 42}));
        assert_eq!(out, "count=42");
    }

    #[test]
    fn render_passes_through_when_no_placeholders() {
        let out = render_template("plain text", &json!({}));
        assert_eq!(out, "plain text");
    }
}

#[derive(sqlx::FromRow)]
struct ChannelRow {
    id: Uuid,
    channel_type: String,
    name: String,
    config_encrypted: String,
    is_active: Option<bool>,
    is_default: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct TemplateRow {
    id: Uuid,
    name: String,
    event_type: String,
    channel_type: String,
    subject: Option<String>,
    body_text: String,
    body_html: Option<String>,
    is_active: Option<bool>,
}

impl From<TemplateRow> for NotificationTemplateResponse {
    fn from(r: TemplateRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            event_type: r.event_type,
            channel_type: r.channel_type,
            subject: r.subject,
            body_text: r.body_text,
            body_html: r.body_html,
            is_active: r.is_active.unwrap_or(true),
        }
    }
}

#[derive(sqlx::FromRow)]
struct PrefRow {
    id: Uuid,
    user_id: Uuid,
    event_type: String,
    channel_types: Vec<String>,
    is_enabled: Option<bool>,
}

impl From<PrefRow> for UserNotificationPreferenceResponse {
    fn from(r: PrefRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            event_type: r.event_type,
            channel_types: r.channel_types,
            is_enabled: r.is_enabled.unwrap_or(true),
        }
    }
}

#[derive(sqlx::FromRow)]
struct InboxRow {
    id: Uuid,
    channel_type: String,
    subject: Option<String>,
    body: String,
    status: Option<String>,
    sent_at: Option<chrono::DateTime<chrono::Utc>>,
    read_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<InboxRow> for NotificationInboxItemResponse {
    fn from(r: InboxRow) -> Self {
        Self {
            id: r.id,
            channel_type: r.channel_type,
            subject: r.subject,
            body: r.body,
            status: r.status.unwrap_or_else(|| "pending".into()),
            sent_at: r.sent_at,
            read_at: r.read_at,
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    name: String,
    event_type: String,
    conditions: serde_json::Value,
    channels: Vec<String>,
    recipients: serde_json::Value,
    template_id: Option<Uuid>,
    is_active: Option<bool>,
}

impl From<RuleRow> for NotificationRuleResponse {
    fn from(r: RuleRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            event_type: r.event_type,
            conditions: r.conditions,
            channels: r.channels,
            recipients: r.recipients,
            template_id: r.template_id,
            is_active: r.is_active.unwrap_or(true),
        }
    }
}
