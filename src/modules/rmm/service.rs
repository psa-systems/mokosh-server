//! RMM service.

use std::sync::Arc;

use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::notifications::render_template;
use crate::modules::tickets::{CreateTicketRequest, TicketService, TicketSource};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

#[derive(Clone)]
pub struct RmmService {
    db: Database,
    encryption_key: [u8; 32],
    /// Alert ingest creates tickets through `TicketService` (validation,
    /// automation engine, audit log, notifications dispatch). There is no
    /// direct-`INSERT` fallback: every RMM-originated ticket goes through
    /// the canonical creation path (PMS-195).
    tickets: Arc<TicketService>,
}

impl RmmService {
    /// Build an `RmmService` wired to the per-deployment data
    /// encryption key. `rmm_connections.api_key_encrypted` /
    /// `api_secret_encrypted` are AES-256-GCM ciphertext under this
    /// key; swapping the key invalidates every stored credential, so
    /// rotate via envelope flow not by passing a different key here.
    ///
    /// There is no zero-key constructor on purpose: a previous version
    /// of this service silently fell back to `[0u8; 32]`, which made
    /// the at-rest encryption a no-op for any caller that forgot to
    /// pass the key (see PMS-103, mirroring the PMS-92 fix on
    /// `NotificationsService`).
    ///
    /// Wires the `TicketService` dependency so RMM-originated tickets go
    /// through the canonical creation path (validation + automation +
    /// audit + notifications). The server uses this constructor in
    /// `create_api_router`.
    pub fn with_dependencies(
        db: Database,
        encryption_key: [u8; 32],
        tickets: TicketService,
    ) -> Self {
        Self {
            db,
            encryption_key,
            tickets: Arc::new(tickets),
        }
    }

    // PMS-102 connections CRUD ------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_connections(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<RmmConnectionResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM rmm_connections WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, ConnRow>(
            r#"SELECT id, name, provider, api_url, is_active, sync_interval_minutes,
                      last_sync_at, sync_status, last_error, created_at
               FROM rmm_connections WHERE tenant_id = $1
               ORDER BY name
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
    pub async fn create_connection(
        &self,
        tenant_id: TenantId,
        request: &CreateRmmConnectionRequest,
        ctx: &AuditCtx,
    ) -> AppResult<RmmConnectionResponse> {
        let key_enc = crate::utils::crypto::encrypt(&request.api_key, &self.encryption_key)?;
        let secret_enc = match &request.api_secret {
            Some(s) => Some(crate::utils::crypto::encrypt(s, &self.encryption_key)?),
            None => None,
        };
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO rmm_connections
               (id, tenant_id, name, provider, api_url, api_key_encrypted,
                api_secret_encrypted, is_active, sync_interval_minutes)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.provider)
        .bind(&request.api_url)
        .bind(&key_enc)
        .bind(&secret_enc)
        .bind(request.is_active)
        .bind(request.sync_interval_minutes)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM rmm_connections t WHERE tenant_id = $1 AND id = $2",
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
            "rmm_connections",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(RmmConnectionResponse {
            id,
            name: request.name.clone(),
            provider: request.provider.clone(),
            api_url: request.api_url.clone(),
            is_active: request.is_active,
            sync_interval_minutes: request.sync_interval_minutes,
            last_sync_at: None,
            sync_status: "never".into(),
            last_error: None,
            created_at: chrono::Utc::now(),
        })
    }

    /// `GET /api/v1/rmm/connections/{id}`. Returns 404 when the row
    /// does not exist in the caller's tenant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_connection(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<RmmConnectionResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<ConnRow> = sqlx::query_as(
            r#"SELECT id, name, provider, api_url, is_active, sync_interval_minutes,
                      last_sync_at, sync_status, last_error, created_at
               FROM rmm_connections WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        row.map(Into::into)
            .ok_or_else(|| AppError::NotFound("RMM connection".to_string()))
    }

    /// `PUT /api/v1/rmm/connections/{id}`. Missing fields on the
    /// request leave the existing column value untouched. `api_key`
    /// and `api_secret` are only re-encrypted when explicitly
    /// supplied; this lets an admin toggle `is_active` without
    /// re-typing the credential. The returned row reflects post-update
    /// state.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_connection(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateRmmConnectionRequest,
    ) -> AppResult<RmmConnectionResponse> {
        let key_enc = match request.api_key.as_deref() {
            Some(k) => Some(crate::utils::crypto::encrypt(k, &self.encryption_key)?),
            None => None,
        };
        let secret_enc = match request.api_secret.as_deref() {
            Some(s) => Some(crate::utils::crypto::encrypt(s, &self.encryption_key)?),
            None => None,
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE rmm_connections SET
                 name = COALESCE($1, name),
                 api_url = COALESCE($2, api_url),
                 api_key_encrypted = COALESCE($3, api_key_encrypted),
                 api_secret_encrypted = COALESCE($4, api_secret_encrypted),
                 is_active = COALESCE($5, is_active),
                 sync_interval_minutes = COALESCE($6, sync_interval_minutes),
                 updated_at = NOW()
               WHERE tenant_id = $7 AND id = $8"#,
        )
        .bind(request.name.as_deref())
        .bind(request.api_url.as_deref())
        .bind(key_enc.as_deref())
        .bind(secret_enc.as_deref())
        .bind(request.is_active)
        .bind(request.sync_interval_minutes)
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RMM connection".to_string()));
        }
        tx.commit().await?;
        self.get_connection(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_connection(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM rmm_connections WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RMM connection".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    /// `POST /api/v1/rmm/connections/:id/test`: probe the RMM endpoint.
    /// v1 just decrypts the credentials and HEADs the api_url to confirm
    /// reachability; per-provider auth check is the next commit.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn test_connection(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<serde_json::Value> {
        let mut read_tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT api_url, api_key_encrypted FROM rmm_connections WHERE tenant_id = $1 AND id = $2",
        ).bind(tenant_id).bind(id).fetch_optional(&mut *read_tx).await?;
        drop(read_tx);
        let Some((url, key_enc)) = row else {
            return Err(AppError::NotFound("RMM connection".to_string()));
        };
        let _api_key = crate::utils::crypto::decrypt(&key_enc, &self.encryption_key)?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::Internal(format!("http client: {e}")))?;
        let result = client
            .head(&url)
            .send()
            .await
            .map(|r| r.status().as_u16())
            .map_err(|e| e.to_string());
        let summary = match result {
            Ok(status) => serde_json::json!({"reachable": true, "status": status}),
            Err(e) => serde_json::json!({"reachable": false, "error": e}),
        };
        let last_sync_status = if summary["reachable"].as_bool().unwrap_or(false) {
            "success"
        } else {
            "failed"
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"UPDATE rmm_connections SET sync_status = $3, last_sync_at = NOW(), updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(last_sync_status)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(summary)
    }

    // PMS-103 device mappings -------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_device_mappings(
        &self,
        tenant_id: TenantId,
        connection_id: Option<Uuid>,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<RmmDeviceMappingResponse>, u64)> {
        // PMS-198: the optional `connection_id` filter is appended
        // dynamically instead of duplicating the whole query in an
        // if/else. Both the COUNT and the page SELECT share the same
        // base predicate plus the conditional `AND rmm_connection_id`.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let mut count_qb =
            sqlx::QueryBuilder::new("SELECT COUNT(*) FROM rmm_device_mappings WHERE tenant_id = ");
        count_qb.push_bind(tenant_id);
        if let Some(cid) = connection_id {
            count_qb.push(" AND rmm_connection_id = ");
            count_qb.push_bind(cid);
        }
        let total: i64 = count_qb.build_query_scalar().fetch_one(&mut *tx).await?;

        let mut rows_qb = sqlx::QueryBuilder::new(
            r#"SELECT id, rmm_connection_id, rmm_device_id, asset_id, company_id,
                      device_name, last_seen, sync_status
               FROM rmm_device_mappings WHERE tenant_id = "#,
        );
        rows_qb.push_bind(tenant_id);
        if let Some(cid) = connection_id {
            rows_qb.push(" AND rmm_connection_id = ");
            rows_qb.push_bind(cid);
        }
        rows_qb.push(" ORDER BY device_name LIMIT ");
        rows_qb.push_bind(pagination.limit() as i64);
        rows_qb.push(" OFFSET ");
        rows_qb.push_bind(pagination.offset() as i64);
        let rows = rows_qb
            .build_query_as::<DevMapRow>()
            .fetch_all(&mut *tx)
            .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_device_mapping(
        &self,
        tenant_id: TenantId,
        request: &CreateRmmDeviceMappingRequest,
        ctx: &AuditCtx,
    ) -> AppResult<RmmDeviceMappingResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO rmm_device_mappings
               (id, tenant_id, rmm_connection_id, rmm_device_id, asset_id, company_id, device_name)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.rmm_connection_id)
        .bind(&request.rmm_device_id)
        .bind(request.asset_id)
        .bind(request.company_id)
        .bind(&request.device_name)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM rmm_device_mappings t WHERE tenant_id = $1 AND id = $2",
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
            "rmm_device_mappings",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(RmmDeviceMappingResponse {
            id,
            rmm_connection_id: request.rmm_connection_id,
            rmm_device_id: request.rmm_device_id.clone(),
            asset_id: request.asset_id,
            company_id: request.company_id,
            device_name: request.device_name.clone(),
            last_seen: None,
            sync_status: "pending".into(),
        })
    }

    /// `GET`-style fetch of a single device mapping. Returns 404 when
    /// the row does not exist in the caller's tenant. Used by
    /// [`Self::update_device_mapping`] to return post-update state.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_device_mapping(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<RmmDeviceMappingResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<DevMapRow> = sqlx::query_as(
            r#"SELECT id, rmm_connection_id, rmm_device_id, asset_id, company_id,
                      device_name, last_seen, sync_status
               FROM rmm_device_mappings WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        row.map(Into::into)
            .ok_or_else(|| AppError::NotFound("RMM device mapping".to_string()))
    }

    /// `PUT /api/v1/rmm/device-mappings/{id}`. Missing fields on the
    /// request leave the existing column value untouched (COALESCE),
    /// matching the connection update semantics. `rmm_connection_id` is
    /// not editable. The returned row reflects post-update state.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_device_mapping(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateRmmDeviceMappingRequest,
    ) -> AppResult<RmmDeviceMappingResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE rmm_device_mappings SET
                 rmm_device_id = COALESCE($1, rmm_device_id),
                 asset_id = COALESCE($2, asset_id),
                 company_id = COALESCE($3, company_id),
                 device_name = COALESCE($4, device_name)
               WHERE tenant_id = $5 AND id = $6"#,
        )
        .bind(request.rmm_device_id.as_deref())
        .bind(request.asset_id)
        .bind(request.company_id)
        .bind(request.device_name.as_deref())
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RMM device mapping".to_string()));
        }
        tx.commit().await?;
        self.get_device_mapping(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_device_mapping(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM rmm_device_mappings WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RMM device mapping".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-104 alert rules + ingestion ----------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_alert_rules(
        &self,
        tenant_id: TenantId,
        connection_id: Option<Uuid>,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<RmmAlertRuleResponse>, u64)> {
        let (total, rows) = if let Some(cid) = connection_id {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            let total: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM rmm_alert_rules WHERE tenant_id = $1 AND rmm_connection_id = $2",
            )
            .bind(tenant_id)
            .bind(cid)
            .fetch_one(&mut *tx)
            .await?;

            let rows = sqlx::query_as::<_, AlertRuleRow>(
                r#"SELECT id, rmm_connection_id, name, alert_type, auto_create_ticket,
                          assign_to_id, queue_id, is_active, ticket_template, suppression_rules
                   FROM rmm_alert_rules WHERE tenant_id = $1 AND rmm_connection_id = $2
                   ORDER BY name
                   LIMIT $3 OFFSET $4"#,
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&mut *tx)
            .await?;
            (total, rows)
        } else {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            let total: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM rmm_alert_rules WHERE tenant_id = $1")
                    .bind(tenant_id)
                    .fetch_one(&mut *tx)
                    .await?;

            let rows = sqlx::query_as::<_, AlertRuleRow>(
                r#"SELECT id, rmm_connection_id, name, alert_type, auto_create_ticket,
                          assign_to_id, queue_id, is_active, ticket_template, suppression_rules
                   FROM rmm_alert_rules WHERE tenant_id = $1
                   ORDER BY name
                   LIMIT $2 OFFSET $3"#,
            )
            .bind(tenant_id)
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&mut *tx)
            .await?;
            (total, rows)
        };
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_alert_rule(
        &self,
        tenant_id: TenantId,
        request: &UpsertRmmAlertRuleRequest,
        ctx: &AuditCtx,
    ) -> AppResult<RmmAlertRuleResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO rmm_alert_rules
               (id, tenant_id, rmm_connection_id, name, alert_type, auto_create_ticket,
                assign_to_id, queue_id, ticket_template, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.rmm_connection_id)
        .bind(&request.name)
        .bind(&request.alert_type)
        .bind(request.auto_create_ticket)
        .bind(request.assign_to_id)
        .bind(request.queue_id)
        .bind(&request.ticket_template)
        .bind(request.is_active)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM rmm_alert_rules t WHERE tenant_id = $1 AND id = $2",
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
            "rmm_alert_rules",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(RmmAlertRuleResponse {
            id,
            rmm_connection_id: request.rmm_connection_id,
            name: request.name.clone(),
            alert_type: request.alert_type.clone(),
            auto_create_ticket: request.auto_create_ticket,
            assign_to_id: request.assign_to_id,
            queue_id: request.queue_id,
            is_active: request.is_active,
        })
    }

    /// `GET`-style fetch of a single alert rule. Returns 404 when the
    /// row does not exist in the caller's tenant. Used by
    /// [`Self::update_alert_rule`] to return post-update state.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_alert_rule(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<RmmAlertRuleResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<AlertRuleRow> = sqlx::query_as(
            r#"SELECT id, rmm_connection_id, name, alert_type, auto_create_ticket,
                      assign_to_id, queue_id, is_active, ticket_template, suppression_rules
               FROM rmm_alert_rules WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        row.map(Into::into)
            .ok_or_else(|| AppError::NotFound("RMM alert rule".to_string()))
    }

    /// `PUT /api/v1/rmm/alert-rules/{id}`. Missing fields on the request
    /// leave the existing column value untouched (COALESCE), matching the
    /// connection update semantics. `rmm_connection_id` is not editable.
    /// The returned row reflects post-update state.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_alert_rule(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateRmmAlertRuleRequest,
    ) -> AppResult<RmmAlertRuleResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE rmm_alert_rules SET
                 name = COALESCE($1, name),
                 alert_type = COALESCE($2, alert_type),
                 auto_create_ticket = COALESCE($3, auto_create_ticket),
                 assign_to_id = COALESCE($4, assign_to_id),
                 queue_id = COALESCE($5, queue_id),
                 ticket_template = COALESCE($6, ticket_template),
                 is_active = COALESCE($7, is_active)
               WHERE tenant_id = $8 AND id = $9"#,
        )
        .bind(request.name.as_deref())
        .bind(request.alert_type.as_deref())
        .bind(request.auto_create_ticket)
        .bind(request.assign_to_id)
        .bind(request.queue_id)
        .bind(request.ticket_template.as_ref())
        .bind(request.is_active)
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RMM alert rule".to_string()));
        }
        tx.commit().await?;
        self.get_alert_rule(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_alert_rule(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM rmm_alert_rules WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RMM alert rule".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Ingest an RMM alert. Matches `(rmm_connection_id, alert_type)`
    /// to active rules; for each rule with `auto_create_ticket = true`
    /// AND whose `suppression_rules` does not gate the alert, creates
    /// a ticket via [`TicketService::create_ticket`] (when wired) so
    /// the result lands with full validation, automation, audit log,
    /// and notifications dispatch. Falls back to a direct INSERT when
    /// the service was built without a dispatcher (legacy fixtures).
    ///
    /// `ticket_template` JSONB (per rule) is rendered with the
    /// notifications `{{key}}` substitution helper against a JSON view
    /// of the alert. The template can override `title` / `description`;
    /// missing fields fall back to the raw `IngestAlertRequest` body.
    ///
    /// HMAC verification is the caller's responsibility (route handler).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn ingest_alert(
        &self,
        tenant_id: TenantId,
        request: &IngestAlertRequest,
    ) -> AppResult<u64> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rules: Vec<AlertRuleRow> = sqlx::query_as(
            r#"SELECT id, rmm_connection_id, name, alert_type, auto_create_ticket,
                      assign_to_id, queue_id, is_active, ticket_template, suppression_rules
               FROM rmm_alert_rules
               WHERE tenant_id = $1 AND rmm_connection_id = $2
                 AND (alert_type = $3 OR alert_type IS NULL)
                 AND is_active = TRUE"#,
        )
        .bind(tenant_id)
        .bind(request.rmm_connection_id)
        .bind(&request.alert_type)
        .fetch_all(&mut *tx)
        .await?;

        let mapping_company: Option<Uuid> = sqlx::query_scalar(
            r#"SELECT company_id FROM rmm_device_mappings
               WHERE tenant_id = $1 AND rmm_connection_id = $2 AND rmm_device_id = $3
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(request.rmm_connection_id)
        .bind(&request.rmm_device_id)
        .fetch_optional(&mut *tx)
        .await?;
        drop(tx);

        let context = serde_json::json!({
            "title": request.title,
            "message": request.message,
            "alert_type": request.alert_type,
            "severity": request.severity,
            "rmm_device_id": request.rmm_device_id,
            "rmm_connection_id": request.rmm_connection_id.to_string(),
        });

        let mut created = 0u64;
        for rule in rules {
            if !rule.auto_create_ticket.unwrap_or(false) {
                continue;
            }
            let Some(company_id) = mapping_company else {
                continue;
            };
            if alert_suppressed(rule.suppression_rules.as_ref(), request) {
                tracing::debug!(
                    rule = %rule.name,
                    alert_type = %request.alert_type,
                    severity = ?request.severity,
                    "rmm alert suppressed by rule.suppression_rules",
                );
                continue;
            }

            // Render title / description from the template if the rule
            // supplies one; otherwise use the raw alert body.
            let (title, description) =
                render_alert_fields(rule.ticket_template.as_ref(), request, &context);

            // Dedupe: skip if an OPEN ticket with the same source/title
            // exists within the dedupe window. Closed tickets are
            // re-eligible so a recurring problem can re-open a ticket.
            if let Some(window) = dedupe_window_minutes(rule.suppression_rules.as_ref()) {
                let mut dedupe_tx = self.db.begin_with_tenant(tenant_id).await?;
                let dup: Option<Uuid> = sqlx::query_scalar(
                    r#"SELECT t.id
                       FROM tickets t
                       JOIN ticket_statuses s ON t.status_id = s.id
                       WHERE t.tenant_id = $1 AND t.source = 'rmm'
                         AND t.company_id = $2 AND t.title = $3
                         AND s.is_closed = FALSE
                         AND t.created_at >= NOW() - ($4 * INTERVAL '1 minute')
                       LIMIT 1"#,
                )
                .bind(tenant_id)
                .bind(company_id)
                .bind(&title)
                .bind(window)
                .fetch_optional(&mut *dedupe_tx)
                .await?;
                drop(dedupe_tx);
                if dup.is_some() {
                    tracing::debug!(
                        rule = %rule.name,
                        window_min = window,
                        "rmm alert dropped by dedupe window",
                    );
                    continue;
                }
            }

            let Some(default_creator) = self.default_creator(tenant_id).await? else {
                continue;
            };
            let req = CreateTicketRequest {
                title: title.clone(),
                description: Some(description.clone()),
                queue_id: rule.queue_id,
                source: TicketSource::Rmm,
                company_id,
                assigned_to_id: rule.assign_to_id,
                is_billable: false,
                ..Default::default()
            };
            // RMM ingest is a background path (no AuditCtx extractor);
            // attribute the auto-created ticket to the system actor.
            // `TicketService` is on `TenantId`, so the scope flows
            // straight through; `AuditCtx::system` is still a `Uuid`
            // context bag, so unwrap only there.
            self.tickets
                .create_ticket(
                    tenant_id,
                    default_creator,
                    &req,
                    &crate::modules::audit::AuditCtx::system(tenant_id.get()),
                )
                .await?;
            created += 1;
        }
        Ok(created)
    }

    async fn default_creator(&self, tenant_id: TenantId) -> AppResult<Option<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Ok(sqlx::query_scalar(
            r#"SELECT id FROM users WHERE tenant_id = $1 AND status = 'active'
                 AND role IN ('super_admin', 'admin', 'manager')
               ORDER BY created_at LIMIT 1"#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?)
    }

    /// PMS-105: verify the HMAC-SHA256 signature on an inbound alert.
    /// Returns the connection's stored secret; the route handler does
    /// the constant-time compare.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn connection_api_secret(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
    ) -> AppResult<Option<String>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<Option<String>> = sqlx::query_scalar(
            "SELECT api_secret_encrypted FROM rmm_connections WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(enc) = row.flatten() else {
            return Ok(None);
        };
        Ok(Some(crate::utils::crypto::decrypt(
            &enc,
            &self.encryption_key,
        )?))
    }
}

#[derive(sqlx::FromRow)]
struct ConnRow {
    id: Uuid,
    name: String,
    provider: String,
    api_url: String,
    is_active: Option<bool>,
    sync_interval_minutes: Option<i32>,
    last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    sync_status: Option<String>,
    last_error: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ConnRow> for RmmConnectionResponse {
    fn from(r: ConnRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            provider: r.provider,
            api_url: r.api_url,
            is_active: r.is_active.unwrap_or(false),
            sync_interval_minutes: r.sync_interval_minutes.unwrap_or(60),
            last_sync_at: r.last_sync_at,
            sync_status: r.sync_status.unwrap_or_else(|| "never".into()),
            last_error: r.last_error,
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct DevMapRow {
    id: Uuid,
    rmm_connection_id: Uuid,
    rmm_device_id: String,
    asset_id: Option<Uuid>,
    company_id: Option<Uuid>,
    device_name: Option<String>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    sync_status: Option<String>,
}

impl From<DevMapRow> for RmmDeviceMappingResponse {
    fn from(r: DevMapRow) -> Self {
        Self {
            id: r.id,
            rmm_connection_id: r.rmm_connection_id,
            rmm_device_id: r.rmm_device_id,
            asset_id: r.asset_id,
            company_id: r.company_id,
            device_name: r.device_name,
            last_seen: r.last_seen,
            sync_status: r.sync_status.unwrap_or_else(|| "pending".into()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct AlertRuleRow {
    id: Uuid,
    rmm_connection_id: Uuid,
    name: String,
    alert_type: Option<String>,
    auto_create_ticket: Option<bool>,
    assign_to_id: Option<Uuid>,
    queue_id: Option<Uuid>,
    is_active: Option<bool>,
    /// JSONB. Shape: `{"title": "{{title}} on {{rmm_device_id}}",
    /// "description": "{{message}}"}`. `{{key}}` placeholders are
    /// resolved against a JSON view of the inbound alert via the
    /// notifications module's `render_template` helper. Missing keys
    /// leave the placeholder intact so an operator can see what was
    /// expected at delivery time.
    ticket_template: Option<serde_json::Value>,
    /// JSONB. Shape: `{"min_severity": "warning",
    /// "dedupe_window_minutes": 15}`. Both fields optional. The
    /// dispatcher consults this BEFORE creating a ticket; suppressed
    /// alerts are dropped after a debug log.
    suppression_rules: Option<serde_json::Value>,
}

impl From<AlertRuleRow> for RmmAlertRuleResponse {
    fn from(r: AlertRuleRow) -> Self {
        Self {
            id: r.id,
            rmm_connection_id: r.rmm_connection_id,
            name: r.name,
            alert_type: r.alert_type,
            auto_create_ticket: r.auto_create_ticket.unwrap_or(false),
            assign_to_id: r.assign_to_id,
            queue_id: r.queue_id,
            is_active: r.is_active.unwrap_or(true),
        }
    }
}

/// Severity ladder used by suppression checks. Anything outside the
/// known set ranks higher than `critical` so unknown severities are
/// never silently dropped.
fn severity_rank(s: Option<&str>) -> u8 {
    match s.unwrap_or("") {
        "low" | "info" => 1,
        "medium" | "warning" => 2,
        "high" => 3,
        "critical" => 4,
        _ => u8::MAX,
    }
}

/// Returns true if the alert is below the rule's `min_severity` (and
/// therefore should be dropped before any ticket is created). When the
/// rule has no `suppression_rules` or no `min_severity` key, returns
/// false (accept).
fn alert_suppressed(rules: Option<&serde_json::Value>, alert: &IngestAlertRequest) -> bool {
    let Some(rules) = rules else {
        return false;
    };
    let Some(min_sev) = rules.get("min_severity").and_then(|v| v.as_str()) else {
        return false;
    };
    severity_rank(alert.severity.as_deref()) < severity_rank(Some(min_sev))
}

/// Pulls `dedupe_window_minutes` out of the rule's `suppression_rules`
/// JSONB. Returns `None` when absent so the caller skips the dedupe
/// SELECT entirely.
fn dedupe_window_minutes(rules: Option<&serde_json::Value>) -> Option<i32> {
    rules?
        .get("dedupe_window_minutes")
        .and_then(|v| v.as_i64())
        .and_then(|n| i32::try_from(n).ok())
        .filter(|n| *n > 0)
}

/// Render the (title, description) fields from the rule's
/// `ticket_template` JSONB. Both fields fall back to the raw alert
/// when the template is missing or omits a key.
fn render_alert_fields(
    template: Option<&serde_json::Value>,
    alert: &IngestAlertRequest,
    context: &serde_json::Value,
) -> (String, String) {
    let raw_title = template
        .and_then(|t| t.get("title"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| alert.title.clone());
    let raw_desc = template
        .and_then(|t| t.get("description"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| alert.message.clone().unwrap_or_default());
    (
        render_template(&raw_title, context).0,
        render_template(&raw_desc, context).0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(severity: Option<&str>) -> IngestAlertRequest {
        IngestAlertRequest {
            rmm_connection_id: Uuid::nil(),
            rmm_device_id: "d1".into(),
            alert_type: "cpu".into(),
            title: "High CPU".into(),
            message: Some("90%".into()),
            severity: severity.map(str::to_string),
        }
    }

    #[test]
    fn suppression_blocks_below_min_severity() {
        let rules = serde_json::json!({"min_severity": "high"});
        assert!(alert_suppressed(Some(&rules), &alert(Some("medium"))));
        assert!(!alert_suppressed(Some(&rules), &alert(Some("high"))));
        assert!(!alert_suppressed(Some(&rules), &alert(Some("critical"))));
    }

    #[test]
    fn suppression_passes_through_when_unset() {
        assert!(!alert_suppressed(None, &alert(Some("low"))));
        let rules = serde_json::json!({});
        assert!(!alert_suppressed(Some(&rules), &alert(Some("low"))));
    }

    #[test]
    fn dedupe_window_extracts_int() {
        let rules = serde_json::json!({"dedupe_window_minutes": 15});
        assert_eq!(dedupe_window_minutes(Some(&rules)), Some(15));
        assert_eq!(dedupe_window_minutes(None), None);
        let zero = serde_json::json!({"dedupe_window_minutes": 0});
        assert_eq!(dedupe_window_minutes(Some(&zero)), None);
    }

    #[test]
    fn render_alert_fields_falls_back_to_raw() {
        let (t, d) = render_alert_fields(None, &alert(Some("high")), &serde_json::json!({}));
        assert_eq!(t, "High CPU");
        assert_eq!(d, "90%");
    }

    #[test]
    fn render_alert_fields_uses_template_with_context() {
        let template = serde_json::json!({
            "title": "{{title}} ({{severity}})",
            "description": "Alert: {{message}}",
        });
        let ctx = serde_json::json!({
            "title": "High CPU",
            "severity": "critical",
            "message": "90%",
        });
        let (t, d) = render_alert_fields(Some(&template), &alert(Some("critical")), &ctx);
        assert_eq!(t, "High CPU (critical)");
        assert_eq!(d, "Alert: 90%");
    }
}
