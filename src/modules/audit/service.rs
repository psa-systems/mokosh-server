//! Audit service.

use crate::modules::auth::TenantId;
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

    #[tracing::instrument(skip_all, fields(tenant_id = ?tenant_id))]
    pub async fn list(
        &self,
        tenant_id: Option<TenantId>,
        filter: &AuditLogFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AuditLogEntryResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;

        // Build the WHERE clause with sequential positional placeholders.
        // The same `where_clause` string is reused by the data and count
        // queries, so the tenant + filter placeholders MUST be numbered
        // identically for both. We number them starting at $1, then the data
        // query appends LIMIT/OFFSET as the LAST two placeholders (bound last);
        // the count query has neither. A previous version started filters at
        // $3, colliding with `OFFSET $3` and binding more values than the
        // statement declared, which 500'd whenever a filter was present
        // (PMS-178).
        let mut conditions: Vec<String> = vec![];
        let mut idx = 1;
        if tenant_id.is_some() {
            conditions.push(format!("tenant_id = ${idx}"));
            idx += 1;
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
            idx += 1;
        }
        let where_clause = if conditions.is_empty() {
            "TRUE".to_string()
        } else {
            conditions.join(" AND ")
        };
        let limit_ph = idx;
        let offset_ph = idx + 1;
        let query = format!(
            r#"SELECT id, tenant_id, user_id, action, entity_type, entity_id,
                      old_values, new_values, ip_address, user_agent, timestamp
               FROM audit_log WHERE {where_clause}
               ORDER BY timestamp DESC LIMIT ${limit_ph} OFFSET ${offset_ph}"#
        );
        let count_query = format!("SELECT COUNT(*) FROM audit_log WHERE {where_clause}");

        let mut q = sqlx::query_as::<_, AuditRow>(&query);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query);
        // Bind tenant + filters in the SAME order for both queries so the
        // shared `where_clause` placeholders line up.
        if let Some(tid) = tenant_id {
            q = q.bind(tid);
            cq = cq.bind(tid);
        }
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
        // Data query binds LIMIT/OFFSET last, matching the appended
        // $limit_ph / $offset_ph; the count query binds neither.
        q = q.bind(limit).bind(offset);

        // When a tenant is in scope, route both reads through a tenant-scoped
        // transaction so the `app.current_tenant` GUC is set. The cross-tenant
        // admin path (`tenant_id == None`) has no tenant value to set and stays
        // on the pool.
        let (rows, total) = if let Some(tid) = tenant_id {
            let mut tx = self.db.begin_with_tenant(tid).await?;
            let rows = q.fetch_all(&mut *tx).await?;
            let total = cq.fetch_one(&mut *tx).await?;
            (rows, total)
        } else {
            let rows = q.fetch_all(self.db.pool()).await?;
            let total = cq.fetch_one(self.db.pool()).await?;
            (rows, total)
        };
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Change history for a single record, newest first. Tenant-scoped and
    /// reads only `audit_log` rows whose `entity_id` matches, so it is safe
    /// to expose to non-admins for the whitelisted entity types
    /// (`HISTORY_ENTITY_TYPES`). Powers the detail-page change-history feeds
    /// in PMS-182 (tickets), PMS-184 (tasks) and projects.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_entity_history(
        &self,
        tenant_id: TenantId,
        entity_type: &str,
        entity_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<EntityHistoryEntry>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE tenant_id = $1 AND entity_type = $2 AND entity_id = $3",
        )
        .bind(tenant_id)
        .bind(entity_type)
        .bind(entity_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, HistoryRow>(
            r#"SELECT id, action, user_id, old_values, new_values, timestamp
               FROM audit_log
               WHERE tenant_id = $1 AND entity_type = $2 AND entity_id = $3
               ORDER BY timestamp DESC LIMIT $4 OFFSET $5"#,
        )
        .bind(tenant_id)
        .bind(entity_type)
        .bind(entity_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }
}

/// Entity types whose change history may be read through the non-admin
/// per-record endpoint. Restricting the set keeps that endpoint from exposing
/// audit trails for sensitive entities (billing, auth) that a technician
/// should not browse, while covering the record types whose detail pages
/// surface a change history (PMS-182/184/185).
pub const HISTORY_ENTITY_TYPES: &[&str] = &["tickets", "tasks", "projects", "assets"];

/// Columns excluded from a record's `changed_fields` diff: bookkeeping that
/// changes on every write and would otherwise drown the meaningful edits.
const HISTORY_NOISE_FIELDS: &[&str] = &[
    "updated_at",
    "created_at",
    "id",
    "tenant_id",
    "last_updated_by_id",
];

/// The before/after value of every column that differs between the two
/// snapshots, noise columns removed and sorted by field name for a stable
/// display order. An empty result (e.g. a create with no `old_values`) means
/// the action label alone carries the information. Shared by the history read
/// path and the asset audit writer (PMS-204).
pub fn field_changes(
    old: &Option<serde_json::Value>,
    new: &Option<serde_json::Value>,
) -> Vec<FieldChange> {
    match (old, new) {
        (Some(serde_json::Value::Object(o)), Some(serde_json::Value::Object(n))) => {
            let mut changes: Vec<FieldChange> = n
                .iter()
                .filter(|(k, v)| o.get(k.as_str()) != Some(*v))
                .filter(|(k, _)| !HISTORY_NOISE_FIELDS.contains(&k.as_str()))
                .map(|(k, v)| FieldChange {
                    field: k.clone(),
                    old: o.get(k).cloned(),
                    new: Some(v.clone()),
                })
                .collect();
            changes.sort_by(|a, b| a.field.cmp(&b.field));
            changes
        }
        _ => Vec::new(),
    }
}

#[derive(sqlx::FromRow)]
struct HistoryRow {
    id: Uuid,
    action: String,
    user_id: Option<Uuid>,
    old_values: Option<serde_json::Value>,
    new_values: Option<serde_json::Value>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl From<HistoryRow> for EntityHistoryEntry {
    fn from(r: HistoryRow) -> Self {
        let changes = field_changes(&r.old_values, &r.new_values);
        let changed_fields = changes.iter().map(|c| c.field.clone()).collect();
        Self {
            id: r.id,
            action: r.action,
            user_id: r.user_id,
            changed_fields,
            changes,
            timestamp: r.timestamp,
        }
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
