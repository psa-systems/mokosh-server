//! Notifications service.
//!
//! Persists channels / templates / preferences / rules and provides a
//! minimal dispatcher: for a given (tenant, event_type) it looks up
//! matching active rules, expands `recipients` (user_ids[] or
//! emails[]), renders a template, and writes one `notifications` row
//! per (recipient, channel) pair. Actual SMTP / Slack / etc. transports
//! are wired by the `notification_dispatcher` worker once it lands; the
//! row's `status = pending` is the queue marker.

use std::collections::HashMap;

use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

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
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<NotificationChannelResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM notification_channels WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, ChannelRow>(
            r#"SELECT id, channel_type, name, config_encrypted, is_active, is_default
               FROM notification_channels WHERE tenant_id = $1
               ORDER BY channel_type, name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        let items = rows
            .into_iter()
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
            .collect::<AppResult<Vec<_>>>()?;
        Ok((items, total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_channel(
        &self,
        tenant_id: TenantId,
        request: &UpsertNotificationChannelRequest,
        ctx: &AuditCtx,
    ) -> AppResult<NotificationChannelResponse> {
        let plain = serde_json::to_string(&request.config)
            .map_err(|e| AppError::BadRequest(format!("Config serialise: {e}")))?;
        let encrypted = crate::utils::crypto::encrypt(&plain, &self.encryption_key)?;
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_channels t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "notification_channels",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(NotificationChannelResponse {
            id,
            channel_type: request.channel_type.clone(),
            name: request.name.clone(),
            config: request.config.clone(),
            is_active: request.is_active,
            is_default: request.is_default,
        })
    }

    /// Full replacement (PUT) of an existing channel. All columns are
    /// overwritten from `request`; `config` is re-encrypted under the
    /// data key. Missing row -> 404. The mutation and its audit row share
    /// one transaction (before/after snapshots), matching the create path.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_channel(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertNotificationChannelRequest,
        ctx: &AuditCtx,
    ) -> AppResult<NotificationChannelResponse> {
        let plain = serde_json::to_string(&request.config)
            .map_err(|e| AppError::BadRequest(format!("Config serialise: {e}")))?;
        let encrypted = crate::utils::crypto::encrypt(&plain, &self.encryption_key)?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_channels t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let n = sqlx::query(
            r#"UPDATE notification_channels SET
                channel_type = $3, name = $4, config_encrypted = $5,
                is_active = $6, is_default = $7, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.channel_type)
        .bind(&request.name)
        .bind(&encrypted)
        .bind(request.is_active)
        .bind(request.is_default)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Notification channel".to_string()));
        }
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_channels t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "notification_channels",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
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
    pub async fn delete_channel(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM notification_channels WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Notification channel".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-88 templates CRUD ---------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_templates(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<NotificationTemplateResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM notification_templates WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, TemplateRow>(
            r#"SELECT id, name, event_type, channel_type, subject, body_text, body_html, is_active
               FROM notification_templates WHERE tenant_id = $1
               ORDER BY event_type, channel_type, name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_template(
        &self,
        tenant_id: TenantId,
        request: &UpsertNotificationTemplateRequest,
        ctx: &AuditCtx,
    ) -> AppResult<NotificationTemplateResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO notification_templates
               (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.event_type).bind(&request.channel_type)
        .bind(&request.subject).bind(&request.body_text).bind(&request.body_html).bind(request.is_active)
        .execute(&mut *tx).await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_templates t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "notification_templates",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
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

    /// Full replacement (PUT) of an existing template. All columns are
    /// overwritten from `request`. Missing row -> 404. Mutation + audit
    /// row share one transaction (before/after snapshots).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_template(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertNotificationTemplateRequest,
        ctx: &AuditCtx,
    ) -> AppResult<NotificationTemplateResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_templates t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let n = sqlx::query(
            r#"UPDATE notification_templates SET
                name = $3, event_type = $4, channel_type = $5, subject = $6,
                body_text = $7, body_html = $8, is_active = $9, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.event_type)
        .bind(&request.channel_type)
        .bind(&request.subject)
        .bind(&request.body_text)
        .bind(&request.body_html)
        .bind(request.is_active)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Notification template".to_string()));
        }
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_templates t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "notification_templates",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
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
    pub async fn delete_template(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM notification_templates WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Notification template".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-89 user preferences -------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_user_preferences(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<UserNotificationPreferenceResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_notification_preferences WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, PrefRow>(
            r#"SELECT id, user_id, event_type, channel_types, is_enabled
               FROM user_notification_preferences
               WHERE tenant_id = $1 AND user_id = $2
               ORDER BY event_type
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_user_preference(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        request: &UpsertUserNotificationPreferenceRequest,
    ) -> AppResult<UserNotificationPreferenceResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
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
        tenant_id: TenantId,
        user_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<NotificationInboxItemResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM notifications
               WHERE tenant_id = $1 AND user_id = $2 AND channel_type = 'in_app'"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, InboxRow>(
            r#"SELECT id, channel_type, subject, body, status, sent_at, read_at, created_at
               FROM notifications
               WHERE tenant_id = $1 AND user_id = $2 AND channel_type = 'in_app'
               ORDER BY created_at DESC
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn mark_read(&self, tenant_id: TenantId, user_id: Uuid, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE notifications SET read_at = NOW()
               WHERE tenant_id = $1 AND user_id = $2 AND id = $3"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Notification".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-91 rules CRUD -------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_rules(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<NotificationRuleResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM notification_rules WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, RuleRow>(
            r#"SELECT id, name, event_type, conditions, channels, recipients, template_id, is_active
               FROM notification_rules WHERE tenant_id = $1
               ORDER BY event_type, name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_rule(
        &self,
        tenant_id: TenantId,
        request: &UpsertNotificationRuleRequest,
        ctx: &AuditCtx,
    ) -> AppResult<NotificationRuleResponse> {
        let template_id = require_template_id(request)?;
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .bind(template_id)
        .bind(request.is_active)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_rules t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "notification_rules",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
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

    /// Full replacement (PUT) of an existing rule. All columns are
    /// overwritten from `request`. Missing row -> 404. Mutation + audit
    /// row share one transaction (before/after snapshots).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_rule(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertNotificationRuleRequest,
        ctx: &AuditCtx,
    ) -> AppResult<NotificationRuleResponse> {
        let template_id = require_template_id(request)?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_rules t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let n = sqlx::query(
            r#"UPDATE notification_rules SET
                name = $3, event_type = $4, conditions = $5, channels = $6,
                recipients = $7, template_id = $8, is_active = $9, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.event_type)
        .bind(&request.conditions)
        .bind(&request.channels)
        .bind(&request.recipients)
        .bind(template_id)
        .bind(request.is_active)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Notification rule".to_string()));
        }
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM notification_rules t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "notification_rules",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
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
    pub async fn delete_rule(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM notification_rules WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Notification rule".to_string()));
        }
        tx.commit().await?;
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
    ///
    /// A rule whose `template_id` is NULL, or whose template row is gone,
    /// is skipped with a `warn!` and contributes nothing to the returned
    /// fanout count (PMS-701).
    ///
    /// PMS-782: the whole call runs in ONE `begin_with_tenant` transaction
    /// (rule lookup, template reads, preference reads and the inserts), and
    /// each fan-out is written with one batched `INSERT ... SELECT ... FROM
    /// UNNEST` per (rule, channel, recipient kind) instead of a transaction
    /// per row. `dispatch` is awaited inline on request paths (a ticket note
    /// add, a password reset), so the round trips were paid by the caller.
    /// The rows are now atomic as a set: a mid-fan-out failure queues nothing
    /// rather than half the recipients, which is the right semantic here
    /// because retries live on the row, not on the dispatch.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn dispatch(
        &self,
        tenant_id: TenantId,
        event_type: &str,
        context: &serde_json::Value,
    ) -> AppResult<u64> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let messages = self
            .render_event(&mut tx, tenant_id, event_type, context)
            .await?;

        let mut fanout = 0u64;
        for message in messages {
            // A placeholder the context cannot supply would otherwise
            // ship as literal braces to the recipient (PMS-702). Only
            // dispatch warns: `preview` renders the same unresolved keys
            // on purpose and returns them to the caller (PMS-808).
            if !message.unresolved.is_empty() {
                tracing::warn!(
                    %tenant_id,
                    event_type,
                    channel = %message.channel,
                    template_id = %message.template_id,
                    unresolved_keys = ?message.unresolved,
                    "notification template has unresolved placeholders",
                );
            }

            // One statement per recipient kind, whatever the recipient count.
            if !message.user_ids.is_empty() {
                fanout += sqlx::query(
                    r#"INSERT INTO notifications
                       (tenant_id, user_id, channel_type, template_id, subject, body, body_html, status)
                       SELECT $1, u, $2, $3, $4, $5, $6, 'pending'
                       FROM UNNEST($7::uuid[]) AS u"#,
                )
                .bind(tenant_id)
                .bind(&message.channel)
                .bind(message.template_id)
                .bind(&message.subject)
                .bind(&message.body_text)
                .bind(&message.body_html)
                .bind(&message.user_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            }
            if !message.emails.is_empty() {
                fanout += sqlx::query(
                    r#"INSERT INTO notifications
                       (tenant_id, channel_type, template_id, recipient, subject, body, body_html, status)
                       SELECT $1, $2, $3, r, $4, $5, $6, 'pending'
                       FROM UNNEST($7::text[]) AS r"#,
                )
                .bind(tenant_id)
                .bind(&message.channel)
                .bind(message.template_id)
                .bind(&message.subject)
                .bind(&message.body_text)
                .bind(&message.body_html)
                .bind(&message.emails)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            }
        }
        tx.commit().await?;
        Ok(fanout)
    }

    /// Render what [`dispatch`](Self::dispatch) would send for
    /// `(event_type, context)` without queueing, sending or writing
    /// anything (PMS-808). One entry per (rule, channel) pair, in the
    /// order `dispatch` processes them.
    ///
    /// Values that only exist at send time (a minted token and its link,
    /// an id assigned on insert) stay unrendered: `render_template`
    /// leaves the literal `{{key}}` in place and the entry's
    /// `unresolved` names it, so the caller can label it rather than
    /// fabricate a sample value.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn preview(
        &self,
        tenant_id: TenantId,
        event_type: &str,
        context: &serde_json::Value,
    ) -> AppResult<Vec<NotificationPreviewResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let messages = self
            .render_event(&mut tx, tenant_id, event_type, context)
            .await?;

        // Recipients are shown as addresses, so a user-id fan-out reads the
        // same way as a standalone email one. The lookup is the same
        // tenant-scoped read the worker does at delivery time; a user whose
        // row is gone shows as its id rather than being dropped, because
        // dispatch would still queue a row for it.
        let user_ids: Vec<Uuid> = messages
            .iter()
            .flat_map(|m| m.user_ids.iter().copied())
            .collect();
        let addresses = self.load_user_emails(&mut tx, tenant_id, &user_ids).await?;
        tx.commit().await?;

        Ok(messages
            .into_iter()
            .map(|m| NotificationPreviewResponse {
                recipients: m
                    .user_ids
                    .iter()
                    .map(|uid| {
                        addresses
                            .get(uid)
                            .cloned()
                            .unwrap_or_else(|| uid.to_string())
                    })
                    .chain(m.emails)
                    .collect(),
                rule_name: m.rule_name,
                channel: m.channel,
                subject: m.subject,
                body_text: m.body_text,
                body_html: m.body_html,
                unresolved: m.unresolved,
            })
            .collect())
    }

    /// The half of the dispatcher that decides WHAT would be sent: rule
    /// lookup, template load, recipient expansion (rule + context, minus
    /// whatever user preferences suppress) and template rendering.
    ///
    /// Shared by [`dispatch`](Self::dispatch), which queues the result,
    /// and [`preview`](Self::preview), which returns it (PMS-808). It is
    /// deliberately one function: a preview rendered by a second copy of
    /// this logic would drift from what actually gets sent, which is
    /// worse than having no preview at all. Nothing here writes.
    ///
    /// Reads run on the caller's connection (PMS-782) so the whole
    /// dispatch, rule lookup through insert, is one transaction.
    async fn render_event(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        event_type: &str,
        context: &serde_json::Value,
    ) -> AppResult<Vec<RenderedNotification>> {
        // PMS-789: the deployment's name is supplied here rather than by each
        // of the dispatch call sites, so no template can name the product and
        // find `{{app_name}}` unresolved because one caller forgot it.
        let merged = with_app_name(context);
        let context = &merged;
        let rules = sqlx::query_as::<_, RuleRow>(
            r#"SELECT id, name, event_type, conditions, channels, recipients, template_id, is_active
               FROM notification_rules
               WHERE tenant_id = $1 AND event_type = $2 AND is_active = TRUE"#,
        )
        .bind(tenant_id)
        .bind(event_type)
        .fetch_all(&mut *conn)
        .await?;

        let ctx_user_id: Option<Uuid> = context
            .get("recipient_user_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());
        let ctx_email: Option<String> = context
            .get("recipient_email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut messages: Vec<RenderedNotification> = Vec::new();
        for rule in rules {
            // PMS-261: scope the template lookup through `begin_with_tenant`
            // so the RLS GUC is set. `notification_templates` carries a
            // `tenant_id` and is covered by the fail-closed policy (migration
            // 038); the previous bare `self.db.pool()` read ran with NO GUC,
            // which under an unprivileged (NOBYPASSRLS) connection matches zero
            // rows and would silently drop the template, falling back to the
            // default subject/body. The `template_id` came off this tenant's
            // own rule, so the row lives under this same tenant.
            let template = match rule.template_id {
                Some(tid) => {
                    sqlx::query_as::<_, TemplateRow>(
                        "SELECT id, name, event_type, channel_type, subject, body_text, body_html, is_active \
                         FROM notification_templates WHERE id = $1",
                    )
                    .bind(tid)
                    .fetch_optional(&mut *conn)
                    .await?
                }
                None => None,
            };

            // PMS-701: no template means nothing renderable. The old
            // fallback body was the whole dispatch JSON (recipient
            // addresses, user ids, ticket text) mailed to a real
            // recipient. Skip the rule and log the misconfiguration.
            let Some(template) = template else {
                tracing::warn!(
                    %tenant_id,
                    event_type,
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    template_id = ?rule.template_id,
                    "notification rule has no usable template; skipping dispatch",
                );
                continue;
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

            // PMS-195: batch-load every recipient's preference row up front
            // instead of querying once per (channel, user) pair inside the
            // nested loop below (was N+1).
            let prefs = self
                .load_user_preferences(&mut *conn, tenant_id, &user_ids, event_type)
                .await?;

            // PMS-782: rendered once per rule, not once per channel. The
            // inputs (this rule's template, the caller's context) do not vary
            // by channel, so every channel of a rule got a byte-identical
            // substitution pass.
            //
            // A template with no subject (in_app rows need none) leaves the
            // column NULL rather than inventing one.
            let (subject, subject_unresolved) = match template.subject.as_deref() {
                Some(raw) => {
                    let (rendered, unresolved) = render_template(raw, context);
                    (Some(rendered), unresolved)
                }
                None => (None, Vec::new()),
            };
            let (body, body_unresolved) = render_template(&template.body_text, context);
            // PMS-700: render the authored HTML alternative alongside the
            // text and persist it on the row, so the worker sends one
            // multipart message instead of re-resolving the template
            // (which could have been edited after the row was queued).
            let (body_html, html_unresolved) = match template.body_html.as_deref() {
                Some(raw) => {
                    let (rendered, unresolved) = render_template(raw, context);
                    (Some(rendered), unresolved)
                }
                None => (None, Vec::new()),
            };
            let mut unresolved = subject_unresolved;
            for key in body_unresolved.into_iter().chain(html_unresolved) {
                if !unresolved.contains(&key) {
                    unresolved.push(key);
                }
            }

            for channel in &rule.channels {
                messages.push(RenderedNotification {
                    rule_name: rule.name.clone(),
                    template_id: template.id,
                    channel: channel.clone(),
                    // Fan out to each user_id, honoring user preferences
                    // for this (event_type, channel) pair.
                    user_ids: user_ids
                        .iter()
                        .copied()
                        .filter(|uid| accepts_channel(prefs.get(uid), channel))
                        .collect(),
                    // Standalone email-style recipients have no user row
                    // and no preferences to consult. in_app rows must
                    // always belong to a user, so they carry none.
                    emails: if channel == "in_app" {
                        Vec::new()
                    } else {
                        emails.clone()
                    },
                    subject: subject.clone(),
                    body_text: body.clone(),
                    body_html: body_html.clone(),
                    unresolved: unresolved.clone(),
                });
            }
        }
        Ok(messages)
    }

    /// Look up the email address of each recipient user in one
    /// tenant-scoped read, keyed by `user_id`. Used by
    /// [`preview`](Self::preview) to show a user fan-out as the address
    /// the worker would actually mail.
    async fn load_user_emails(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        user_ids: &[Uuid],
    ) -> AppResult<HashMap<Uuid, String>> {
        if user_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, email FROM users WHERE tenant_id = $1 AND id = ANY($2)")
                .bind(tenant_id)
                .bind(user_ids)
                .fetch_all(&mut *conn)
                .await?;
        Ok(rows.into_iter().collect())
    }

    /// Batch-load the `user_notification_preferences` rows for every
    /// recipient in one query (PMS-195), keyed by `user_id`. A user with
    /// no row is simply absent from the map (treated as accept-all by
    /// [`accepts_channel`]).
    async fn load_user_preferences(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        user_ids: &[Uuid],
        event_type: &str,
    ) -> AppResult<HashMap<Uuid, (Option<bool>, Vec<String>)>> {
        if user_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, Option<bool>, Vec<String>)> = sqlx::query_as(
            r#"SELECT user_id, is_enabled, channel_types
               FROM user_notification_preferences
               WHERE tenant_id = $1 AND user_id = ANY($2) AND event_type = $3"#,
        )
        .bind(tenant_id)
        .bind(user_ids)
        .bind(event_type)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(uid, enabled, channels)| (uid, (enabled, channels)))
            .collect())
    }
}

/// One (rule, channel) pair after rule lookup, template load, recipient
/// expansion and rendering: exactly what `dispatch` is about to queue,
/// and what `preview` returns instead of queueing it (PMS-808).
struct RenderedNotification {
    rule_name: String,
    template_id: Uuid,
    channel: String,
    /// Recipients with a `users` row, already filtered by their
    /// notification preferences for this (event_type, channel).
    user_ids: Vec<Uuid>,
    /// Standalone addresses with no `users` row. Always empty on the
    /// `in_app` channel, which needs a user to show the row to.
    emails: Vec<String>,
    subject: Option<String>,
    body_text: String,
    body_html: Option<String>,
    /// De-duplicated `{{key}}` names that the context did not carry,
    /// across subject, text body and HTML body.
    unresolved: Vec<String>,
}

/// Decide whether a recipient should receive `channel`, given their
/// preference row (or `None` if they have no row). Absent row = accept
/// (project default). Row with `is_enabled = false` = reject. Row with
/// `is_enabled = true` = accept only if `channel_types` contains the
/// channel.
fn accepts_channel(pref: Option<&(Option<bool>, Vec<String>)>, channel: &str) -> bool {
    match pref {
        None => true,
        Some((enabled, channels)) => {
            if !enabled.unwrap_or(true) {
                return false;
            }
            channels.iter().any(|c| c == channel)
        }
    }
}

/// Tracing target of the per-render event emitted by
/// [`render_template`]. Exported so a test can count renders without
/// hardcoding a module path.
pub const RENDER_TRACE_TARGET: &str = "mokosh::notifications::render";

/// Add `app_name` to a render context, overwriting any value the caller
/// supplied (PMS-789).
///
/// Overwriting rather than defaulting: the product name is a property of the
/// deployment, so a caller-supplied one would let context data rename the
/// product in an outbound email. A context that is not an object carries no
/// top-level keys for `render_template` to resolve anyway, so replacing it
/// loses nothing.
fn with_app_name(context: &serde_json::Value) -> serde_json::Value {
    let name = serde_json::Value::String(crate::utils::app_name::app_name().to_string());
    let mut merged = context.clone();
    match merged.as_object_mut() {
        Some(obj) => {
            obj.insert("app_name".to_string(), name);
        }
        None => {
            let mut obj = serde_json::Map::new();
            obj.insert("app_name".to_string(), name);
            merged = serde_json::Value::Object(obj);
        }
    }
    merged
}

/// Minimal `{{key}}` substitution. Keys are resolved against the
/// top-level fields of `context`; missing keys leave the placeholder
/// untouched so an operator can see what was expected at delivery time.
/// String values render verbatim; other JSON values render as their
/// `Display` representation.
///
/// Returns the rendered text plus the de-duplicated list of keys that
/// did not resolve (PMS-702), so the caller can log a template typo
/// instead of shipping literal braces to a customer.
/// PMS-701: a rule without a template can never render a message, so
/// reject it at write time instead of letting `dispatch` skip it later.
/// The route-level `#[validate(required)]` catches the HTTP path; this
/// covers every other caller of the service.
fn require_template_id(request: &UpsertNotificationRuleRequest) -> AppResult<Uuid> {
    request
        .template_id
        .ok_or_else(|| AppError::validation_field("template_id", "is required"))
}

pub fn render_template(input: &str, context: &serde_json::Value) -> (String, Vec<String>) {
    // PMS-782: one trace event per substitution pass, so the render count of a
    // dispatch is observable (it used to be one pass per channel of the same
    // rule, rendering byte-identical output N times).
    tracing::trace!(target: RENDER_TRACE_TARGET, bytes = input.len(), "rendering notification template");
    let mut out = String::with_capacity(input.len());
    let mut unresolved: Vec<String> = Vec::new();
    let mut rest = input;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        rest = &rest[open + 2..];
        let Some(close) = rest.find("}}") else {
            out.push_str("{{");
            out.push_str(rest);
            return (out, unresolved);
        };
        let key = rest[..close].trim();
        match context.get(key) {
            Some(serde_json::Value::String(s)) => out.push_str(s),
            Some(v) => out.push_str(&v.to_string()),
            None => {
                if !unresolved.iter().any(|k| k == key) {
                    unresolved.push(key.to_string());
                }
                out.push_str("{{");
                out.push_str(&rest[..close]);
                out.push_str("}}");
            }
        }
        rest = &rest[close + 2..];
    }
    out.push_str(rest);
    (out, unresolved)
}

#[cfg(test)]
mod tests {
    use super::{render_template, require_template_id, UpsertNotificationRuleRequest};
    use serde_json::json;
    use uuid::Uuid;
    use validator::Validate;

    #[test]
    fn render_substitutes_string_keys() {
        let (out, unresolved) = render_template(
            "Hi {{name}}, see {{link}}",
            &json!({"name": "Pat", "link": "https://x"}),
        );
        assert_eq!(out, "Hi Pat, see https://x");
        assert!(unresolved.is_empty());
    }

    #[test]
    fn render_leaves_missing_keys_intact() {
        let (out, unresolved) = render_template("Hello {{absent}}", &json!({}));
        assert_eq!(out, "Hello {{absent}}");
        assert_eq!(unresolved, vec!["absent".to_string()]);
    }

    #[test]
    fn render_reports_each_unresolved_key_once() {
        let (_, unresolved) = render_template(
            "{{ticket.number}} {{ticket.number}} {{ticket_title}}",
            &json!({"ticket_title": "Boom"}),
        );
        assert_eq!(unresolved, vec!["ticket.number".to_string()]);
    }

    #[test]
    fn render_handles_non_string_values() {
        let (out, unresolved) = render_template("count={{n}}", &json!({"n": 42}));
        assert_eq!(out, "count=42");
        assert!(unresolved.is_empty());
    }

    #[test]
    fn render_passes_through_when_no_placeholders() {
        let (out, unresolved) = render_template("plain text", &json!({}));
        assert_eq!(out, "plain text");
        assert!(unresolved.is_empty());
    }

    #[test]
    fn rule_without_template_fails_validation() {
        let req: UpsertNotificationRuleRequest = serde_json::from_value(json!({
            "name": "No template",
            "event_type": "test.event",
            "channels": ["email"],
            "recipients": {"emails": ["ops@example.test"]},
        }))
        .expect("deserialise rule request");

        let errors = req.validate().expect_err("missing template_id must fail");
        assert!(
            errors.field_errors().contains_key("template_id"),
            "expected a template_id field error, got {errors:?}",
        );
        let err = require_template_id(&req).expect_err("service guard must reject too");
        assert_eq!(err.status_code(), 422, "must surface as a validation error");
    }

    #[test]
    fn rule_with_template_passes_validation() {
        let req: UpsertNotificationRuleRequest = serde_json::from_value(json!({
            "name": "With template",
            "event_type": "test.event",
            "channels": ["email"],
            "recipients": {"emails": ["ops@example.test"]},
            "template_id": Uuid::new_v4(),
        }))
        .expect("deserialise rule request");
        req.validate().expect("template_id present validates");
        require_template_id(&req).expect("service guard accepts");
    }

    /// PMS-701: `dispatch` used to fall back to a synthetic subject and a
    /// body holding the serialized dispatch context (recipient addresses,
    /// user ids, ticket text). Fail if either literal reappears anywhere
    /// under `src/`. The needles are split so this guard never matches
    /// itself.
    #[test]
    fn no_context_dump_fallback_in_source() {
        let needles = [
            concat!("Mokosh ", "event:"),
            concat!("fired with ", "context"),
        ];
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut hits: Vec<String> = Vec::new();
        let mut dirs = vec![root.join("src"), root.join("tests"), root.join("crates")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("read source file");
                    for needle in needles {
                        if text.contains(needle) {
                            hits.push(format!("{}: {needle}", path.display()));
                        }
                    }
                }
            }
        }
        assert!(
            hits.is_empty(),
            "notification fallback subject/body is back: {hits:?}",
        );
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
