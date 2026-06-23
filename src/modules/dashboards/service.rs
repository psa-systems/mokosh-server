//! PMS-453: saved dashboards service.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::models::{
    CreateSavedDashboardRequest, SavedDashboardResponse, UpdateSavedDashboardRequest,
};
use crate::utils::error::{AppError, AppResult};

#[derive(Debug, FromRow)]
struct DashboardRow {
    id: Uuid,
    name: String,
    layout: serde_json::Value,
    is_default: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<DashboardRow> for SavedDashboardResponse {
    fn from(r: DashboardRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            layout: r.layout,
            is_default: r.is_default,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Clone)]
pub struct DashboardsService {
    pool: PgPool,
}

impl DashboardsService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List the caller's own saved dashboards. Default-first so the
    /// SPA's dashboard switcher can render the pinned row at the top
    /// without re-sorting client-side.
    pub async fn list_mine(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<SavedDashboardResponse>> {
        let rows = sqlx::query_as::<_, DashboardRow>(
            "SELECT id, name, layout, is_default, created_at, updated_at \
             FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 \
             ORDER BY is_default DESC, name ASC",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
    ) -> AppResult<SavedDashboardResponse> {
        let row = sqlx::query_as::<_, DashboardRow>(
            "SELECT id, name, layout, is_default, created_at, updated_at \
             FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 AND id = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::NotFound("Dashboard not found".into()))?;
        Ok(row.into())
    }

    pub async fn create(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        req: CreateSavedDashboardRequest,
    ) -> AppResult<SavedDashboardResponse> {
        let mut tx = self.pool.begin().await?;
        // If the caller asked for is_default, clear any existing
        // default for the same (tenant, user) so the partial-unique
        // index does not conflict.
        if req.is_default {
            sqlx::query(
                "UPDATE saved_dashboards SET is_default = false, updated_at = NOW() \
                 WHERE tenant_id = $1 AND user_id = $2 AND is_default = true",
            )
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }
        let row = sqlx::query_as::<_, DashboardRow>(
            "INSERT INTO saved_dashboards (tenant_id, user_id, name, layout, is_default) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, name, layout, is_default, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(req.name)
        .bind(req.layout)
        .bind(req.is_default)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.into())
    }

    pub async fn update(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
        req: UpdateSavedDashboardRequest,
    ) -> AppResult<SavedDashboardResponse> {
        let mut tx = self.pool.begin().await?;
        // Confirm the row exists in the caller's scope before touching
        // anything; surface a 404 instead of a silent no-op.
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 AND id = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound("Dashboard not found".into()));
        }
        // Promoting a row to default clears the previous default in
        // the same transaction so the partial-unique index is
        // satisfied.
        if matches!(req.is_default, Some(true)) {
            sqlx::query(
                "UPDATE saved_dashboards SET is_default = false, updated_at = NOW() \
                 WHERE tenant_id = $1 AND user_id = $2 AND is_default = true AND id <> $3",
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        let row = sqlx::query_as::<_, DashboardRow>(
            "UPDATE saved_dashboards SET \
                 name = COALESCE($4, name), \
                 layout = COALESCE($5, layout), \
                 is_default = COALESCE($6, is_default), \
                 updated_at = NOW() \
             WHERE tenant_id = $1 AND user_id = $2 AND id = $3 \
             RETURNING id, name, layout, is_default, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(id)
        .bind(req.name)
        .bind(req.layout)
        .bind(req.is_default)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.into())
    }

    pub async fn delete(&self, tenant_id: Uuid, user_id: Uuid, id: Uuid) -> AppResult<()> {
        let rows = sqlx::query(
            "DELETE FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 AND id = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if rows == 0 {
            return Err(AppError::NotFound("Dashboard not found".into()));
        }
        Ok(())
    }

    /// Fast path used by the SPA on app boot: returns the caller's
    /// default dashboard if one is pinned, otherwise `None`. Pulled
    /// into its own method so the client can `GET
    /// /dashboards/default` without paying for the full list scan.
    pub async fn get_default(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Option<SavedDashboardResponse>> {
        let row = sqlx::query_as::<_, DashboardRow>(
            "SELECT id, name, layout, is_default, created_at, updated_at \
             FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 AND is_default = true \
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }
}
