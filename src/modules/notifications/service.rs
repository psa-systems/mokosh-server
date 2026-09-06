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
        self.list_inbox_for(tenant_id, InboxOwner::User(user_id), pagination)
            .await
    }

    /// PMS-1083: the contact arm of `GET /notifications`, the rows the
    /// dispatcher wrote against `notifications.contact_id`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contact_id = %contact_id))]
    pub async fn list_inbox_for_contact(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<NotificationInboxItemResponse>, u64)> {
        self.list_inbox_for(tenant_id, InboxOwner::Contact(contact_id), pagination)
            .await
    }

    async fn list_inbox_for(
        &self,
        tenant_id: TenantId,
        owner: InboxOwner,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<NotificationInboxItemResponse>, u64)> {
        // Two statements per owner kind rather than one with a CASE, so
        // each stays on its own partial index (migrations 013 and 142).
        let (count_sql, list_sql, owner_id) = match owner {
            InboxOwner::User(id) => (
                r#"SELECT COUNT(*) FROM notifications
                   WHERE tenant_id = $1 AND user_id = $2 AND channel_type = 'in_app'"#,
                r#"SELECT id, channel_type, subject, body, status, sent_at, read_at, created_at,
                          entity_type, entity_id
                   FROM notifications
                   WHERE tenant_id = $1 AND user_id = $2 AND channel_type = 'in_app'
                   ORDER BY created_at DESC
                   LIMIT $3 OFFSET $4"#,
                id,
            ),
            InboxOwner::Contact(id) => (
                r#"SELECT COUNT(*) FROM notifications
                   WHERE tenant_id = $1 AND contact_id = $2 AND channel_type = 'in_app'"#,
                r#"SELECT id, channel_type, subject, body, status, sent_at, read_at, created_at,
                          entity_type, entity_id
                   FROM notifications
                   WHERE tenant_id = $1 AND contact_id = $2 AND channel_type = 'in_app'
                   ORDER BY created_at DESC
                   LIMIT $3 OFFSET $4"#,
                id,
            ),
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(count_sql)
            .bind(tenant_id)
            .bind(owner_id)
            .fetch_one(&mut *tx)
            .await?;
        let rows = sqlx::query_as::<_, InboxRow>(list_sql)
            .bind(tenant_id)
            .bind(owner_id)
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&mut *tx)
            .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn mark_read(&self, tenant_id: TenantId, user_id: Uuid, id: Uuid) -> AppResult<()> {
        self.mark_read_for(tenant_id, InboxOwner::User(user_id), id)
            .await
    }

    /// PMS-1083: the contact arm of `POST /notifications/{id}/read`. A
    /// row that is not the contact's own is a 404, never a 403, so the
    /// route confirms nothing about another inbox.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contact_id = %contact_id))]
    pub async fn mark_read_for_contact(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        id: Uuid,
    ) -> AppResult<()> {
        self.mark_read_for(tenant_id, InboxOwner::Contact(contact_id), id)
            .await
    }

    async fn mark_read_for(
        &self,
        tenant_id: TenantId,
        owner: InboxOwner,
        id: Uuid,
    ) -> AppResult<()> {
        let (sql, owner_id) = match owner {
            InboxOwner::User(id) => (
                r#"UPDATE notifications SET read_at = NOW()
                   WHERE tenant_id = $1 AND user_id = $2 AND id = $3"#,
                id,
            ),
            InboxOwner::Contact(id) => (
                r#"UPDATE notifications SET read_at = NOW()
                   WHERE tenant_id = $1 AND contact_id = $2 AND id = $3"#,
                id,
            ),
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(sql)
            .bind(tenant_id)
            .bind(owner_id)
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

    // PMS-729 phase 2 §6 slice 5: branding-context injection ---------------

    /// Fold `{{msp_name}}` / `{{msp_logo_url}}` / `{{msp_primary_color}}`
    /// / `{{msp_support_email}}` into the render context so every
    /// template gets tenant-branded output without the dispatch caller
    /// having to thread the fields in by hand.
    ///
    /// Missing branding fields degrade to empty strings so a template
    /// that references `{{msp_support_email}}` on a tenant that never
    /// set one renders `""` (empty) rather than a literal placeholder;
    /// this matches what `render_template` already does for absent
    /// keys but is more graceful for user-visible copy.
    /// `{{msp_name}}` defaults to "Mokosh Platform" so subject lines
    /// like "{{msp_name}} - Reset your password" stay readable even for
    /// the default/system tenant.
    ///
    /// Caller-supplied keys ALWAYS win: a test that passes an explicit
    /// `msp_name` in context sees that value, not the DB one.
    ///
    /// Reads `tenants` on the caller's connection (PMS-1068), whose
    /// transaction has already set the tenant GUC, rather than opening a
    /// second one of its own.
    async fn enrich_with_branding(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        mut context: serde_json::Value,
    ) -> AppResult<serde_json::Value> {
        // The template context must be a JSON object to merge into. If
        // a caller passed a non-object (empty array, null, primitive),
        // wrap it in an object so the branding keys can be attached
        // rather than silently dropped.
        if !context.is_object() {
            context = serde_json::json!({});
        }

        let row: Option<(String, serde_json::Value)> =
            sqlx::query_as(r#"SELECT name, branding FROM tenants WHERE id = $1"#)
                .bind(tenant_id)
                .fetch_optional(&mut *conn)
                .await?;

        let (name, branding) = match row {
            Some(r) => r,
            None => (String::new(), serde_json::json!({})),
        };

        let obj = context.as_object_mut().expect("guarded above");

        // helper: only set the key if the caller did not.
        let mut ensure_key = |k: &str, v: serde_json::Value| {
            if !obj.contains_key(k) {
                obj.insert(k.to_string(), v);
            }
        };

        let msp_name = if name.is_empty() {
            "Mokosh Platform".to_string()
        } else {
            name
        };
        ensure_key("msp_name", serde_json::Value::String(msp_name));

        let branding_str = |field: &str| -> String {
            branding
                .get(field)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_default()
        };
        ensure_key(
            "msp_logo_url",
            serde_json::Value::String(branding_str("logo_url")),
        );
        ensure_key(
            "msp_primary_color",
            serde_json::Value::String(branding_str("primary_color")),
        );
        ensure_key(
            "msp_support_email",
            serde_json::Value::String(branding_str("support_email")),
        );

        Ok(context)
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
    ///
    /// PMS-1068: the branding read and the template batch load had drifted back
    /// out of that transaction into two of their own, so the reads that decided
    /// WHAT to queue could not see the transaction that queued it. Both now run
    /// on the caller's connection, and
    /// `tests/notification_dispatch_query_budget.rs` counts the `set_config`
    /// and the `COMMIT` so a third cannot come back unnoticed.
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
                       (tenant_id, user_id, channel_type, template_id, subject, body, body_html,
                        status, entity_type, entity_id)
                       SELECT $1, u, $2, $3, $4, $5, $6, 'pending', $8, $9
                       FROM UNNEST($7::uuid[]) AS u"#,
                )
                .bind(tenant_id)
                .bind(&message.channel)
                .bind(message.template_id)
                .bind(&message.subject)
                .bind(&message.body_text)
                .bind(&message.body_html)
                .bind(&message.user_ids)
                .bind(&message.entity_type)
                .bind(message.entity_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            }
            if !message.emails.is_empty() {
                fanout += sqlx::query(
                    r#"INSERT INTO notifications
                       (tenant_id, channel_type, template_id, recipient, subject, body, body_html,
                        status, entity_type, entity_id)
                       SELECT $1, $2, $3, r, $4, $5, $6, 'pending', $8, $9
                       FROM UNNEST($7::text[]) AS r"#,
                )
                .bind(tenant_id)
                .bind(&message.channel)
                .bind(message.template_id)
                .bind(&message.subject)
                .bind(&message.body_text)
                .bind(&message.body_html)
                .bind(&message.emails)
                .bind(&message.entity_type)
                .bind(message.entity_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            }
            // PMS-1083: the contact's inbox row, against `contact_id`
            // (migration 142). `contact_ids` is empty off the `in_app`
            // channel by construction.
            if !message.contact_ids.is_empty() {
                fanout += sqlx::query(
                    r#"INSERT INTO notifications
                       (tenant_id, contact_id, channel_type, template_id, subject, body, body_html,
                        status, entity_type, entity_id)
                       SELECT $1, c, $2, $3, $4, $5, $6, 'pending', $8, $9
                       FROM UNNEST($7::uuid[]) AS c"#,
                )
                .bind(tenant_id)
                .bind(&message.channel)
                .bind(message.template_id)
                .bind(&message.subject)
                .bind(&message.body_text)
                .bind(&message.body_html)
                .bind(&message.contact_ids)
                .bind(&message.entity_type)
                .bind(message.entity_id)
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
        // PMS-729 phase 2 §6 slice 5: enrich the render context with the
        // MSP's identity (name + branding) so every template can reference
        // `{{msp_name}}` / `{{msp_logo_url}}` / `{{msp_primary_color}}` /
        // `{{msp_support_email}}` without the caller having to thread those
        // values through by hand. Caller-supplied context keys always win
        // over the branding defaults so a specific dispatch site can
        // override. Applied here (not in dispatch) so `preview` renders the
        // same context and neither can drift.
        let enriched_context = self
            .enrich_with_branding(&mut *conn, tenant_id, context.clone())
            .await?;
        // PMS-789: the deployment's name is supplied here rather than by each
        // of the dispatch call sites, so no template can name the product and
        // find `{{app_name}}` unresolved because one caller forgot it.
        let merged = with_app_name(&enriched_context);
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
        // PMS-729 phase 2 §7 slice B / I12: portal-inbox recipient. When a
        // caller stamps `recipient_contact_id` into the context, the
        // dispatcher writes an in_app row against `notifications.contact_id`
        // so the portal inbox picks it up. Rule-level contact recipients
        // (a `contacts` array under `notification_rules.recipients` JSONB)
        // are supported alongside the ctx key.
        let ctx_contact_id: Option<Uuid> = context
            .get("recipient_contact_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        // Per-entity deep-link metadata. When the caller stamps
        // `entity_type` (`ticket` / `invoice` / `quote` / ...) and
        // `entity_id` into the context, the dispatcher persists both
        // onto every notification row so the portal inbox can render
        // a click-through link straight to the entity's detail page.
        // Absent / malformed values simply skip the columns and leave
        // NULL (matches the auth.* / system-event case, where there
        // is no single entity to deep-link). Stamped on every row of
        // every recipient kind since PMS-1083 (MAPPS-656 recorded the
        // pair as parsed and never written).
        let ctx_entity_type: Option<String> = context
            .get("entity_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty() && s.chars().count() <= 50);
        let ctx_entity_id: Option<Uuid> = context
            .get("entity_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        // Batch-load every distinct template id off the rules in one
        // round-trip. Previously the loop below opened one
        // `begin_with_tenant` tx PER rule to fetch the template by id
        // (N+1 against `notification_templates`); a busy dispatch with
        // 4-5 rules on the same event would spend most of its wall-
        // clock on template lookups. One IN() call keyed by tenant
        // still passes the RLS policy (same GUC posture per PMS-261):
        // it runs on the caller's connection, whose transaction already
        // set the GUC, rather than opening a second one (PMS-1068).
        let template_ids: Vec<Uuid> = rules.iter().filter_map(|r| r.template_id).collect();
        let template_index: HashMap<Uuid, TemplateRow> = if template_ids.is_empty() {
            HashMap::new()
        } else {
            let rows: Vec<TemplateRow> = sqlx::query_as(
                "SELECT id, name, event_type, channel_type, subject, body_text, body_html, is_active \
                 FROM notification_templates WHERE id = ANY($1)",
            )
            .bind(&template_ids)
            .fetch_all(&mut *conn)
            .await?;
            rows.into_iter().map(|t| (t.id, t)).collect()
        };

        let mut messages: Vec<RenderedNotification> = Vec::new();
        for rule in rules {
            // PMS-782 batch: templates were loaded up front (see
            // `template_index` above), so the per-rule lookup is one hash hit
            // rather than a round-trip. Main's per-rule fetch was PMS-261's
            // RLS-safe read; the batch runs inside the caller's tenant
            // transaction and therefore keeps the RLS GUC set for the read.
            let template = rule
                .template_id
                .and_then(|tid| template_index.get(&tid).cloned());

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

            // PMS-729 phase 2 §7 slice B / I12: contact recipients. Same
            // shape as user_ids / emails; a rule can enumerate
            // `contacts: [uuid, ...]` in its recipients JSONB, and the
            // dispatch caller can add one more via
            // `recipient_contact_id`. Deduplicated so a caller stamping
            // the same contact twice does not double the fanout.
            let mut contact_ids: Vec<Uuid> = rule
                .recipients
                .get("contacts")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect();
            if let Some(cid) = ctx_contact_id {
                if !contact_ids.contains(&cid) {
                    contact_ids.push(cid);
                }
            }

            // PMS-195: batch-load every recipient's preference row up front
            // instead of querying once per (channel, user) pair inside the
            // nested loop below (was N+1).
            let prefs = self
                .load_user_preferences(&mut *conn, tenant_id, &user_ids, event_type)
                .await?;
            // Portal notification-preferences: same shape as user prefs
            // but keyed on contact_id (see contact_notification_preferences,
            // migration 120). A contact who opted out sees no fanout on
            // in_app for this event (PMS-1083).
            let contact_prefs = self
                .load_contact_preferences(&mut *conn, tenant_id, &contact_ids, event_type)
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
                    // PMS-1083: a contact is an inbox recipient only. On
                    // any other channel the row would need an address the
                    // dispatcher does not resolve for a contact.
                    contact_ids: if channel == "in_app" {
                        contact_ids
                            .iter()
                            .copied()
                            .filter(|cid| accepts_channel(contact_prefs.get(cid), channel))
                            .collect()
                    } else {
                        Vec::new()
                    },
                    entity_type: ctx_entity_type.clone(),
                    entity_id: ctx_entity_id,
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

    /// Portal parallel of [`Self::load_user_preferences`]: batch-load
    /// every recipient contact's `contact_notification_preferences`
    /// row for the current event_type, keyed by `contact_id`. A
    /// contact with no row is absent from the map (accept-all).
    async fn load_contact_preferences(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_ids: &[Uuid],
        event_type: &str,
    ) -> AppResult<HashMap<Uuid, (Option<bool>, Vec<String>)>> {
        if contact_ids.is_empty() {
            return Ok(HashMap::new());
        }
        // On the dispatch's own connection, so a contact recipient does
        // not open a second transaction beside the one the fanout is in
        // (the PMS-782 budget: one BEGIN per dispatch).
        let rows: Vec<(Uuid, Option<bool>, Vec<String>)> = sqlx::query_as(
            r#"SELECT contact_id, is_enabled, channel_types
               FROM contact_notification_preferences
               WHERE tenant_id = $1 AND contact_id = ANY($2) AND event_type = $3"#,
        )
        .bind(tenant_id)
        .bind(contact_ids)
        .bind(event_type)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(cid, enabled, channels)| (cid, (enabled, channels)))
            .collect())
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
    /// `in_app` channel, which needs a user or a contact to show the
    /// row to.
    emails: Vec<String>,
    /// PMS-1083: recipients with a `contacts` row, already filtered by
    /// their `contact_notification_preferences` for this (event_type,
    /// channel). Written against `notifications.contact_id` on the
    /// `in_app` channel only: a contact's inbox is what the contact
    /// plane reads, and a contact's email goes through the existing
    /// `recipient_email` path where the caller chose to send one.
    contact_ids: Vec<Uuid>,
    /// Per-entity deep link stamped on every row this message queues
    /// (`context.entity_type` / `context.entity_id`, migration 150).
    entity_type: Option<String>,
    entity_id: Option<Uuid>,
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

#[derive(Clone, sqlx::FromRow)]
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
    entity_type: Option<String>,
    entity_id: Option<Uuid>,
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
            entity_type: r.entity_type,
            entity_id: r.entity_id,
        }
    }
}

/// PMS-1083: whose inbox a read addresses. A staff user's rows hang
/// off `notifications.user_id`, a contact's off `contact_id`
/// (migration 142); the two never share a row.
#[derive(Debug, Clone, Copy)]
enum InboxOwner {
    User(Uuid),
    Contact(Uuid),
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

/// PMS-1068: the reads that decide what a dispatch queues run inside the
/// transaction that queues it.
///
/// [`NotificationsService::dispatch`] and [`NotificationsService::preview`]
/// each open one `begin_with_tenant` transaction and hand the connection to
/// [`NotificationsService::render_event`]. A read inside `render_event` that
/// opens its own transaction instead runs on a second connection, so it cannot
/// see the caller's uncommitted writes, and it costs the caller a BEGIN, a
/// `set_config` and a rollback per read on a path that is awaited inline on
/// request handling.
///
/// That is not a rule the compiler can express: `self.db` is in scope
/// throughout, so `begin_with_tenant` compiles anywhere. PMS-782 stated the
/// rule in a doc comment and two later changes broke it anyway (the PMS-729
/// branding read, and the template batch load that replaced a per-rule
/// transaction with one transaction where it needed none), so the source is
/// what gets read - the `billing::routes::finance_gate` and
/// `contacts::service::mirror_writers` shape, under `cargo test --lib`, with
/// no script, recipe or CI step to add.
///
/// `tests/notification_dispatch_query_budget.rs` is the behavioural half: this
/// scan proves no transaction is opened in the render path, that test counts
/// the `set_config` and the `COMMIT` a real dispatch actually issues.
#[cfg(test)]
mod one_transaction_per_dispatch {
    /// The functions that run on the caller's connection and must never open a
    /// transaction of their own.
    const RENDER_PATH: &[&str] = &["async fn render_event(", "async fn enrich_with_branding("];

    /// Return the body of the function whose signature starts at `start`, by
    /// matching braces from the signature's opening `{`. Every brace in these
    /// bodies is balanced (`{{key}}` placeholders in comments come in pairs,
    /// as does `json!({})`), so a plain depth count is enough.
    fn body_of(text: &str, start: usize) -> &str {
        let open = start
            + text[start..]
                .find('{')
                .expect("a function signature is followed by its body");
        let mut depth = 0usize;
        for (offset, ch) in text[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &text[open..open + offset + 1];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces after the signature at byte {start}");
    }

    #[test]
    fn no_read_in_the_render_path_opens_its_own_transaction() {
        // The CALL, not the name: `render_event` carries a comment recounting
        // the per-rule transaction the template batch replaced, and a mention
        // in prose is not a transaction. Assembled so the needle is not its own
        // hit either.
        let needle = format!(".begin_with{}(", "_tenant");
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(file!());
        let text = std::fs::read_to_string(&path).expect("read this source file");

        let mut offenders: Vec<&str> = Vec::new();
        for signature in RENDER_PATH {
            let start = text.find(signature).unwrap_or_else(|| {
                panic!("{signature} is gone; rename it here or the guard scans nothing")
            });
            if body_of(&text, start).contains(&needle) {
                offenders.push(signature);
            }
        }

        assert!(
            offenders.is_empty(),
            "these run on the caller's connection and must not open a transaction \
             of their own (PMS-1068); read on the `conn` argument instead: {offenders:?}",
        );
    }
}
