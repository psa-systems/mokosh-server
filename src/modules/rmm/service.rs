//! RMM service.

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

use super::models::*;

#[derive(Clone)]
pub struct RmmService {
    db: Database,
    encryption_key: [u8; 32],
}

impl RmmService {
    pub fn new(db: Database) -> Self {
        Self { db, encryption_key: [0u8; 32] }
    }

    pub fn with_encryption_key(db: Database, encryption_key: [u8; 32]) -> Self {
        Self { db, encryption_key }
    }

    // PMS-102 connections CRUD ------------------------------------------------
    pub async fn list_connections(&self, tenant_id: Uuid) -> AppResult<Vec<RmmConnectionResponse>> {
        let rows = sqlx::query_as::<_, ConnRow>(
            r#"SELECT id, name, provider, api_url, is_active, sync_interval_minutes,
                      last_sync_at, sync_status, last_error, created_at
               FROM rmm_connections WHERE tenant_id = $1 ORDER BY name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_connection(
        &self, tenant_id: Uuid, request: &CreateRmmConnectionRequest,
    ) -> AppResult<RmmConnectionResponse> {
        let key_enc = crate::utils::crypto::encrypt(&request.api_key, &self.encryption_key)?;
        let secret_enc = match &request.api_secret {
            Some(s) => Some(crate::utils::crypto::encrypt(s, &self.encryption_key)?),
            None => None,
        };
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO rmm_connections
               (id, tenant_id, name, provider, api_url, api_key_encrypted,
                api_secret_encrypted, is_active, sync_interval_minutes)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.provider).bind(&request.api_url)
        .bind(&key_enc).bind(&secret_enc).bind(request.is_active).bind(request.sync_interval_minutes)
        .execute(self.db.pool()).await?;
        Ok(RmmConnectionResponse {
            id, name: request.name.clone(), provider: request.provider.clone(),
            api_url: request.api_url.clone(),
            is_active: request.is_active, sync_interval_minutes: request.sync_interval_minutes,
            last_sync_at: None, sync_status: "never".into(), last_error: None,
            created_at: chrono::Utc::now(),
        })
    }

    pub async fn delete_connection(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM rmm_connections WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("RmmConnection".to_string())); }
        Ok(())
    }

    /// `POST /api/v1/rmm/connections/:id/test`: probe the RMM endpoint.
    /// v1 just decrypts the credentials and HEADs the api_url to confirm
    /// reachability; per-provider auth check is the next commit.
    pub async fn test_connection(&self, tenant_id: Uuid, id: Uuid) -> AppResult<serde_json::Value> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT api_url, api_key_encrypted FROM rmm_connections WHERE tenant_id = $1 AND id = $2",
        ).bind(tenant_id).bind(id).fetch_optional(self.db.pool()).await?;
        let Some((url, key_enc)) = row else {
            return Err(AppError::NotFound("RmmConnection".to_string()));
        };
        let _api_key = crate::utils::crypto::decrypt(&key_enc, &self.encryption_key)?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::Internal(format!("http client: {e}")))?;
        let result = client.head(&url).send().await
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
        sqlx::query(
            r#"UPDATE rmm_connections SET sync_status = $3, last_sync_at = NOW(), updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        ).bind(tenant_id).bind(id).bind(last_sync_status)
        .execute(self.db.pool()).await?;
        Ok(summary)
    }

    // PMS-103 device mappings -------------------------------------------------
    pub async fn list_device_mappings(
        &self, tenant_id: Uuid, connection_id: Option<Uuid>,
    ) -> AppResult<Vec<RmmDeviceMappingResponse>> {
        let rows = if let Some(cid) = connection_id {
            sqlx::query_as::<_, DevMapRow>(
                r#"SELECT id, rmm_connection_id, rmm_device_id, asset_id, company_id,
                          device_name, last_seen, sync_status
                   FROM rmm_device_mappings WHERE tenant_id = $1 AND rmm_connection_id = $2
                   ORDER BY device_name"#,
            ).bind(tenant_id).bind(cid).fetch_all(self.db.pool()).await?
        } else {
            sqlx::query_as::<_, DevMapRow>(
                r#"SELECT id, rmm_connection_id, rmm_device_id, asset_id, company_id,
                          device_name, last_seen, sync_status
                   FROM rmm_device_mappings WHERE tenant_id = $1 ORDER BY device_name"#,
            ).bind(tenant_id).fetch_all(self.db.pool()).await?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_device_mapping(
        &self, tenant_id: Uuid, request: &CreateRmmDeviceMappingRequest,
    ) -> AppResult<RmmDeviceMappingResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO rmm_device_mappings
               (id, tenant_id, rmm_connection_id, rmm_device_id, asset_id, company_id, device_name)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(request.rmm_connection_id).bind(&request.rmm_device_id)
        .bind(request.asset_id).bind(request.company_id).bind(&request.device_name)
        .execute(self.db.pool()).await?;
        Ok(RmmDeviceMappingResponse {
            id, rmm_connection_id: request.rmm_connection_id,
            rmm_device_id: request.rmm_device_id.clone(),
            asset_id: request.asset_id, company_id: request.company_id,
            device_name: request.device_name.clone(),
            last_seen: None, sync_status: "pending".into(),
        })
    }

    pub async fn delete_device_mapping(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM rmm_device_mappings WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("RmmDeviceMapping".to_string())); }
        Ok(())
    }

    // PMS-104 alert rules + ingestion ----------------------------------------
    pub async fn list_alert_rules(
        &self, tenant_id: Uuid, connection_id: Option<Uuid>,
    ) -> AppResult<Vec<RmmAlertRuleResponse>> {
        let rows = if let Some(cid) = connection_id {
            sqlx::query_as::<_, AlertRuleRow>(
                r#"SELECT id, rmm_connection_id, name, alert_type, auto_create_ticket,
                          assign_to_id, queue_id, is_active
                   FROM rmm_alert_rules WHERE tenant_id = $1 AND rmm_connection_id = $2
                   ORDER BY name"#,
            ).bind(tenant_id).bind(cid).fetch_all(self.db.pool()).await?
        } else {
            sqlx::query_as::<_, AlertRuleRow>(
                r#"SELECT id, rmm_connection_id, name, alert_type, auto_create_ticket,
                          assign_to_id, queue_id, is_active
                   FROM rmm_alert_rules WHERE tenant_id = $1 ORDER BY name"#,
            ).bind(tenant_id).fetch_all(self.db.pool()).await?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_alert_rule(
        &self, tenant_id: Uuid, request: &UpsertRmmAlertRuleRequest,
    ) -> AppResult<RmmAlertRuleResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO rmm_alert_rules
               (id, tenant_id, rmm_connection_id, name, alert_type, auto_create_ticket,
                assign_to_id, queue_id, ticket_template, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(id).bind(tenant_id).bind(request.rmm_connection_id)
        .bind(&request.name).bind(&request.alert_type).bind(request.auto_create_ticket)
        .bind(request.assign_to_id).bind(request.queue_id)
        .bind(&request.ticket_template).bind(request.is_active)
        .execute(self.db.pool()).await?;
        Ok(RmmAlertRuleResponse {
            id, rmm_connection_id: request.rmm_connection_id,
            name: request.name.clone(), alert_type: request.alert_type.clone(),
            auto_create_ticket: request.auto_create_ticket,
            assign_to_id: request.assign_to_id, queue_id: request.queue_id,
            is_active: request.is_active,
        })
    }

    pub async fn delete_alert_rule(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM rmm_alert_rules WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("RmmAlertRule".to_string())); }
        Ok(())
    }

    /// Ingest an RMM alert. Matches `(rmm_connection_id, alert_type)`
    /// to active rules; for each rule with `auto_create_ticket = true`,
    /// inserts a ticket attributed to the rule's `assign_to_id` queue.
    /// HMAC verification is the caller's responsibility (route handler).
    pub async fn ingest_alert(
        &self, tenant_id: Uuid, request: &IngestAlertRequest,
    ) -> AppResult<u64> {
        let rules: Vec<AlertRuleRow> = sqlx::query_as(
            r#"SELECT id, rmm_connection_id, name, alert_type, auto_create_ticket,
                      assign_to_id, queue_id, is_active
               FROM rmm_alert_rules
               WHERE tenant_id = $1 AND rmm_connection_id = $2
                 AND (alert_type = $3 OR alert_type IS NULL)
                 AND is_active = TRUE"#,
        )
        .bind(tenant_id).bind(request.rmm_connection_id).bind(&request.alert_type)
        .fetch_all(self.db.pool()).await?;

        let mapping_company: Option<Uuid> = sqlx::query_scalar(
            r#"SELECT company_id FROM rmm_device_mappings
               WHERE tenant_id = $1 AND rmm_connection_id = $2 AND rmm_device_id = $3
               LIMIT 1"#,
        )
        .bind(tenant_id).bind(request.rmm_connection_id).bind(&request.rmm_device_id)
        .fetch_optional(self.db.pool()).await?;

        let mut created = 0u64;
        for rule in rules {
            if !rule.auto_create_ticket.unwrap_or(false) { continue; }
            let Some(company_id) = mapping_company else { continue; };
            let Some(default_creator) = self.default_creator(tenant_id).await? else { continue; };
            let default_status: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
            ).bind(tenant_id).fetch_optional(self.db.pool()).await?;
            let default_priority: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
            ).bind(tenant_id).fetch_optional(self.db.pool()).await?;
            let queue_id: Option<Uuid> = match rule.queue_id {
                Some(q) => Some(q),
                None => sqlx::query_scalar(
                    "SELECT id FROM ticket_queues WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
                ).bind(tenant_id).fetch_optional(self.db.pool()).await?,
            };
            let Some(status_id) = default_status else { continue; };
            let Some(priority_id) = default_priority else { continue; };
            let Some(queue_id) = queue_id else { continue; };

            let ticket_number: i32 = sqlx::query_scalar(
                r#"UPDATE ticket_sequences SET last_number = last_number + 1
                   WHERE tenant_id = $1 RETURNING last_number"#,
            ).bind(tenant_id).fetch_one(self.db.pool()).await?;
            let id = Uuid::new_v4();
            sqlx::query(
                r#"INSERT INTO tickets (
                    id, tenant_id, ticket_number, title, description, status_id,
                    priority_id, queue_id, source, company_id, assigned_to_id,
                    is_billable, created_by_id
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'rmm',$9,$10,FALSE,$11)"#,
            )
            .bind(id).bind(tenant_id).bind(format!("T{:06}", ticket_number))
            .bind(&request.title).bind(&request.message)
            .bind(status_id).bind(priority_id).bind(queue_id)
            .bind(company_id).bind(rule.assign_to_id).bind(default_creator)
            .execute(self.db.pool()).await?;
            created += 1;
        }
        Ok(created)
    }

    async fn default_creator(&self, tenant_id: Uuid) -> AppResult<Option<Uuid>> {
        Ok(sqlx::query_scalar(
            r#"SELECT id FROM users WHERE tenant_id = $1 AND status = 'active'
                 AND role IN ('super_admin', 'admin', 'manager')
               ORDER BY created_at LIMIT 1"#,
        ).bind(tenant_id).fetch_optional(self.db.pool()).await?)
    }

    /// PMS-105: verify the HMAC-SHA256 signature on an inbound alert.
    /// Returns the connection's stored secret; the route handler does
    /// the constant-time compare.
    pub async fn connection_api_secret(
        &self, tenant_id: Uuid, connection_id: Uuid,
    ) -> AppResult<Option<String>> {
        let row: Option<Option<String>> = sqlx::query_scalar(
            "SELECT api_secret_encrypted FROM rmm_connections WHERE tenant_id = $1 AND id = $2",
        ).bind(tenant_id).bind(connection_id).fetch_optional(self.db.pool()).await?;
        let Some(enc) = row.flatten() else { return Ok(None); };
        Ok(Some(crate::utils::crypto::decrypt(&enc, &self.encryption_key)?))
    }
}

#[derive(sqlx::FromRow)]
struct ConnRow {
    id: Uuid, name: String, provider: String, api_url: String,
    is_active: Option<bool>, sync_interval_minutes: Option<i32>,
    last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    sync_status: Option<String>, last_error: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ConnRow> for RmmConnectionResponse {
    fn from(r: ConnRow) -> Self {
        Self {
            id: r.id, name: r.name, provider: r.provider, api_url: r.api_url,
            is_active: r.is_active.unwrap_or(false),
            sync_interval_minutes: r.sync_interval_minutes.unwrap_or(60),
            last_sync_at: r.last_sync_at,
            sync_status: r.sync_status.unwrap_or_else(|| "never".into()),
            last_error: r.last_error, created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct DevMapRow {
    id: Uuid, rmm_connection_id: Uuid, rmm_device_id: String,
    asset_id: Option<Uuid>, company_id: Option<Uuid>,
    device_name: Option<String>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    sync_status: Option<String>,
}

impl From<DevMapRow> for RmmDeviceMappingResponse {
    fn from(r: DevMapRow) -> Self {
        Self {
            id: r.id, rmm_connection_id: r.rmm_connection_id,
            rmm_device_id: r.rmm_device_id,
            asset_id: r.asset_id, company_id: r.company_id,
            device_name: r.device_name, last_seen: r.last_seen,
            sync_status: r.sync_status.unwrap_or_else(|| "pending".into()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct AlertRuleRow {
    id: Uuid, rmm_connection_id: Uuid, name: String,
    alert_type: Option<String>, auto_create_ticket: Option<bool>,
    assign_to_id: Option<Uuid>, queue_id: Option<Uuid>,
    is_active: Option<bool>,
}

impl From<AlertRuleRow> for RmmAlertRuleResponse {
    fn from(r: AlertRuleRow) -> Self {
        Self {
            id: r.id, rmm_connection_id: r.rmm_connection_id,
            name: r.name, alert_type: r.alert_type,
            auto_create_ticket: r.auto_create_ticket.unwrap_or(false),
            assign_to_id: r.assign_to_id, queue_id: r.queue_id,
            is_active: r.is_active.unwrap_or(true),
        }
    }
}
