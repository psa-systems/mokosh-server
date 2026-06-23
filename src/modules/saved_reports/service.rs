//! PMS-457: saved-reports service.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::models::{CreateSavedReportRequest, SavedReportResponse, UpdateSavedReportRequest};
use crate::utils::error::{AppError, AppResult};

#[derive(Debug, FromRow)]
struct ReportRow {
    id: Uuid,
    created_by_id: Uuid,
    created_by_name: Option<String>,
    name: String,
    description: Option<String>,
    entity_type: String,
    filters: serde_json::Value,
    columns: serde_json::Value,
    group_by: serde_json::Value,
    sort: serde_json::Value,
    is_shared: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<ReportRow> for SavedReportResponse {
    fn from(r: ReportRow) -> Self {
        Self {
            id: r.id,
            created_by_id: r.created_by_id,
            created_by_name: r.created_by_name,
            name: r.name,
            description: r.description,
            entity_type: r.entity_type,
            filters: r.filters,
            columns: r.columns,
            group_by: r.group_by,
            sort: r.sort,
            is_shared: r.is_shared,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Visibility scope used by `list`.
#[derive(Debug, Clone, Copy)]
pub enum ReportScope {
    /// Reports authored by the caller. Always returned.
    Mine,
    /// `is_shared=true` reports, regardless of author.
    Shared,
    /// Union of `Mine` and `Shared`. Used as the SPA's default
    /// "everything I can see" landing list.
    Any,
}

const SELECT_FIELDS: &str = "
    r.id,
    r.created_by_id,
    NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), '') AS created_by_name,
    r.name, r.description, r.entity_type,
    r.filters, r.columns, r.group_by, r.sort,
    r.is_shared, r.created_at, r.updated_at
";

#[derive(Clone)]
pub struct SavedReportsService {
    pool: PgPool,
}

impl SavedReportsService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List reports visible to `user_id` under `scope`. Filters by
    /// `entity_type` when supplied so the entity-page sidebar can
    /// ask "what saved reports target this entity".
    pub async fn list(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        scope: ReportScope,
        entity_type: Option<&str>,
    ) -> AppResult<Vec<SavedReportResponse>> {
        // The visibility predicate composes the scope with the
        // optional entity filter. Building the SQL by concat keeps
        // the bind-positions stable across all four shapes.
        let scope_clause = match scope {
            ReportScope::Mine => "r.created_by_id = $2",
            ReportScope::Shared => "r.is_shared = true",
            ReportScope::Any => "(r.created_by_id = $2 OR r.is_shared = true)",
        };
        let entity_clause = if entity_type.is_some() {
            " AND r.entity_type = $3"
        } else {
            ""
        };
        let sql = format!(
            "SELECT {SELECT_FIELDS} \
             FROM saved_reports r \
             LEFT JOIN users u ON u.id = r.created_by_id \
             WHERE r.tenant_id = $1 AND ({scope_clause}){entity_clause} \
             ORDER BY r.updated_at DESC",
        );
        let mut q = sqlx::query_as::<_, ReportRow>(&sql)
            .bind(tenant_id)
            .bind(user_id);
        if let Some(et) = entity_type {
            q = q.bind(et);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
    ) -> AppResult<SavedReportResponse> {
        let sql = format!(
            "SELECT {SELECT_FIELDS} \
             FROM saved_reports r \
             LEFT JOIN users u ON u.id = r.created_by_id \
             WHERE r.tenant_id = $1 AND r.id = $2 \
               AND (r.created_by_id = $3 OR r.is_shared = true)",
        );
        let row = sqlx::query_as::<_, ReportRow>(&sql)
            .bind(tenant_id)
            .bind(id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AppError::NotFound("SavedReport".into()))?;
        Ok(row.into())
    }

    pub async fn create(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        req: CreateSavedReportRequest,
    ) -> AppResult<SavedReportResponse> {
        let inserted: Uuid = sqlx::query_scalar(
            "INSERT INTO saved_reports \
                 (tenant_id, created_by_id, name, description, entity_type, \
                  filters, columns, group_by, sort, is_shared) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.entity_type)
        .bind(&req.filters)
        .bind(&req.columns)
        .bind(&req.group_by)
        .bind(&req.sort)
        .bind(req.is_shared)
        .fetch_one(&self.pool)
        .await?;
        self.get(tenant_id, user_id, inserted).await
    }

    /// PATCH a saved report. Only the author may mutate it; another
    /// viewer (who can see a shared report) gets 404 on attempt to
    /// keep the response shape uniform with absent rows.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
        req: UpdateSavedReportRequest,
    ) -> AppResult<SavedReportResponse> {
        let owner: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM saved_reports \
             WHERE tenant_id = $1 AND id = $2 AND created_by_id = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        if owner.is_none() {
            return Err(AppError::NotFound("SavedReport".into()));
        }
        sqlx::query(
            "UPDATE saved_reports SET \
                 name = COALESCE($4, name), \
                 description = COALESCE($5, description), \
                 filters = COALESCE($6, filters), \
                 columns = COALESCE($7, columns), \
                 group_by = COALESCE($8, group_by), \
                 sort = COALESCE($9, sort), \
                 is_shared = COALESCE($10, is_shared), \
                 updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 AND created_by_id = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .bind(req.name)
        .bind(req.description)
        .bind(req.filters)
        .bind(req.columns)
        .bind(req.group_by)
        .bind(req.sort)
        .bind(req.is_shared)
        .execute(&self.pool)
        .await?;
        self.get(tenant_id, user_id, id).await
    }

    pub async fn delete(&self, tenant_id: Uuid, user_id: Uuid, id: Uuid) -> AppResult<()> {
        let rows = sqlx::query(
            "DELETE FROM saved_reports \
             WHERE tenant_id = $1 AND id = $2 AND created_by_id = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if rows == 0 {
            return Err(AppError::NotFound("SavedReport".into()));
        }
        Ok(())
    }
}
