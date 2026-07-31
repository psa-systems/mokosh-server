//! PMS-453: saved dashboards service.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::models::{
    CreateSavedDashboardRequest, CreateScheduledDashboardRequest, SavedDashboardResponse,
    ScheduledDashboardResponse, UpdateSavedDashboardRequest, UpdateScheduledDashboardRequest,
};
use crate::db::Database;
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

/// PMS-683: every query runs inside `Database::begin_with_tenant`, which sets
/// the `app.current_tenant` GUC transaction-locally, so `saved_dashboards` and
/// `scheduled_dashboards` are safe under the fail-closed `tenant_isolation` RLS
/// policy (migration 095). The cross-tenant sweep in ScheduledDashboardsWorker
/// uses the BYPASSRLS migrator pool.
#[derive(Clone)]
pub struct DashboardsService {
    db: Database,
}

impl DashboardsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// List the caller's own saved dashboards. Default-first so the
    /// SPA's dashboard switcher can render the pinned row at the top
    /// without re-sorting client-side.
    pub async fn list_mine(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<SavedDashboardResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, DashboardRow>(
            "SELECT id, name, layout, is_default, created_at, updated_at \
             FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 \
             ORDER BY is_default DESC, name ASC",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
    ) -> AppResult<SavedDashboardResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, DashboardRow>(
            "SELECT id, name, layout, is_default, created_at, updated_at \
             FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 AND id = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(id)
        .fetch_optional(&mut *tx)
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query(
            "DELETE FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 AND id = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, DashboardRow>(
            "SELECT id, name, layout, is_default, created_at, updated_at \
             FROM saved_dashboards \
             WHERE tenant_id = $1 AND user_id = $2 AND is_default = true \
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(row.map(Into::into))
    }

    // PMS-471: schedule machinery ------------------------------------------

    /// Create a schedule for the dashboard. Re-uses the `get`
    /// visibility rule so a user can only schedule their own
    /// dashboards (saved dashboards are private by design).
    pub async fn schedule_create(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        dashboard_id: Uuid,
        req: CreateScheduledDashboardRequest,
    ) -> AppResult<ScheduledDashboardResponse> {
        let _ = self.get(tenant_id, user_id, dashboard_id).await?;
        let next_run = compute_next_run(&req.cron_expr, Utc::now())?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO scheduled_dashboards \
                 (tenant_id, dashboard_id, user_id, cron_expr, \
                  recipient_email, is_active, next_run_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(dashboard_id)
        .bind(user_id)
        .bind(&req.cron_expr)
        .bind(&req.recipient_email)
        .bind(req.is_active)
        .bind(next_run)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        self.schedule_get(tenant_id, id).await
    }

    pub async fn schedule_list(
        &self,
        tenant_id: Uuid,
        dashboard_id: Uuid,
    ) -> AppResult<Vec<ScheduledDashboardResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, ScheduleRow>(
            "SELECT id, dashboard_id, user_id, cron_expr, channel, \
                    recipient_email, is_active, last_run_at, next_run_at, \
                    last_error, created_at, updated_at \
             FROM scheduled_dashboards \
             WHERE tenant_id = $1 AND dashboard_id = $2 \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .bind(dashboard_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn schedule_get(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AppResult<ScheduledDashboardResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ScheduleRow>(
            "SELECT id, dashboard_id, user_id, cron_expr, channel, \
                    recipient_email, is_active, last_run_at, next_run_at, \
                    last_error, created_at, updated_at \
             FROM scheduled_dashboards \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound("ScheduledDashboard".into()))?;
        Ok(row.into())
    }

    pub async fn schedule_update(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
        req: UpdateScheduledDashboardRequest,
    ) -> AppResult<ScheduledDashboardResponse> {
        let new_next: Option<DateTime<Utc>> = match req.cron_expr.as_deref() {
            Some(expr) => Some(compute_next_run(expr, Utc::now())?),
            None => None,
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query(
            "UPDATE scheduled_dashboards SET \
                 cron_expr       = COALESCE($4, cron_expr), \
                 next_run_at     = COALESCE($5, next_run_at), \
                 recipient_email = COALESCE($6, recipient_email), \
                 is_active       = COALESCE($7, is_active), \
                 updated_at      = NOW() \
             WHERE tenant_id = $1 AND id = $2 AND user_id = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .bind(req.cron_expr)
        .bind(new_next)
        .bind(req.recipient_email)
        .bind(req.is_active)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if rows == 0 {
            return Err(AppError::NotFound("ScheduledDashboard".into()));
        }
        self.schedule_get(tenant_id, id).await
    }

    pub async fn schedule_delete(&self, tenant_id: Uuid, user_id: Uuid, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query(
            "DELETE FROM scheduled_dashboards \
             WHERE tenant_id = $1 AND id = $2 AND user_id = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if rows == 0 {
            return Err(AppError::NotFound("ScheduledDashboard".into()));
        }
        Ok(())
    }
}

#[derive(Debug, FromRow)]
struct ScheduleRow {
    id: Uuid,
    dashboard_id: Uuid,
    user_id: Uuid,
    cron_expr: String,
    channel: String,
    recipient_email: Option<String>,
    is_active: bool,
    last_run_at: Option<DateTime<Utc>>,
    next_run_at: DateTime<Utc>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<ScheduleRow> for ScheduledDashboardResponse {
    fn from(r: ScheduleRow) -> Self {
        Self {
            id: r.id,
            dashboard_id: r.dashboard_id,
            user_id: r.user_id,
            cron_expr: r.cron_expr,
            channel: r.channel,
            recipient_email: r.recipient_email,
            is_active: r.is_active,
            last_run_at: r.last_run_at,
            next_run_at: r.next_run_at,
            last_error: r.last_error,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// PMS-471: parse + advance a cron expression. Returns the next
/// firing strictly after `anchor`. Mirrors
/// `saved_reports::service::compute_next_run` but is kept module-local
/// rather than shared via `utils` to avoid forming a coupling between
/// two unrelated feature modules over a 5-line helper.
pub(crate) fn compute_next_run(expr: &str, anchor: DateTime<Utc>) -> AppResult<DateTime<Utc>> {
    use std::str::FromStr;
    let schedule = cron::Schedule::from_str(expr)
        .map_err(|e| AppError::BadRequest(format!("Invalid cron expression: {e}")))?;
    schedule
        .after(&anchor)
        .next()
        .ok_or_else(|| AppError::Internal(format!("Cron '{expr}' has no future firings")))
}
