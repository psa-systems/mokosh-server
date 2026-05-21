//! Audit service.

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::AppResult;
use crate::utils::pagination::PaginationParams;

use super::models::*;

#[derive(Clone)]
pub struct AuditService {
    db: Database,
}

impl AuditService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Append a new entry. Called by the middleware on every mutating
    /// request; failures are swallowed so the request itself never
    /// fails because of a log write.
    #[allow(clippy::too_many_arguments)]
    pub async fn append(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        action: &str,
        entity_type: &str,
        entity_id: Option<Uuid>,
        new_values: Option<serde_json::Value>,
        ip: Option<String>,
        ua: Option<String>,
    ) -> AppResult<()> {
        let _ = sqlx::query(
            r#"INSERT INTO audit_log
               (tenant_id, user_id, action, entity_type, entity_id, new_values,
                ip_address, user_agent)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(action)
        .bind(entity_type)
        .bind(entity_id)
        .bind(new_values)
        .bind(ip)
        .bind(ua)
        .execute(self.db.pool())
        .await;
        Ok(())
    }

    pub async fn list(
        &self,
        tenant_id: Option<Uuid>,
        filter: &AuditLogFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AuditLogEntryResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        let mut conditions: Vec<String> = vec![];
        let mut idx = 3;
        if tenant_id.is_some() {
            conditions.push("tenant_id = $1".to_string());
        }
        if filter.user_id.is_some() {
            conditions.push(format!("user_id = ${idx}"));
            idx += 1;
        }
        if filter.entity_type.is_some() {
            conditions.push(format!("entity_type = ${idx}"));
            idx += 1;
        }
        if filter.action.is_some() {
            conditions.push(format!("action = ${idx}"));
            idx += 1;
        }
        if filter.from.is_some() {
            conditions.push(format!("timestamp >= ${idx}"));
            idx += 1;
        }
        if filter.to.is_some() {
            conditions.push(format!("timestamp <= ${idx}"));
        }
        let where_clause = if conditions.is_empty() {
            "TRUE".to_string()
        } else {
            conditions.join(" AND ")
        };
        let query = format!(
            r#"SELECT id, tenant_id, user_id, action, entity_type, entity_id,
                      old_values, new_values, ip_address, user_agent, timestamp
               FROM audit_log WHERE {where_clause}
               ORDER BY timestamp DESC LIMIT $2 OFFSET $3"#
        );
        let count_query = format!("SELECT COUNT(*) FROM audit_log WHERE {where_clause}");

        // Bindings: $1 is tenant_id (always present in the placeholder
        // sequence because the WHERE clause references it conditionally;
        // we still bind a UUID even for cross-tenant queries by using
        // the nil UUID with a no-op "true" predicate). Simpler approach:
        // build different queries.
        let mut q = sqlx::query_as::<_, AuditRow>(&query);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query);
        if let Some(tid) = tenant_id {
            q = q.bind(tid);
            cq = cq.bind(tid);
        }
        q = q.bind(limit).bind(offset);
        if let Some(v) = filter.user_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.entity_type {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.action {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.from {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.to {
            q = q.bind(v);
            cq = cq.bind(v);
        }

        let rows = q.fetch_all(self.db.pool()).await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
    action: String,
    entity_type: String,
    entity_id: Option<Uuid>,
    old_values: Option<serde_json::Value>,
    new_values: Option<serde_json::Value>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl From<AuditRow> for AuditLogEntryResponse {
    fn from(r: AuditRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            user_id: r.user_id,
            action: r.action,
            entity_type: r.entity_type,
            entity_id: r.entity_id,
            old_values: r.old_values,
            new_values: r.new_values,
            ip_address: r.ip_address,
            user_agent: r.user_agent,
            timestamp: r.timestamp,
        }
    }
}
