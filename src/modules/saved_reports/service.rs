//! PMS-457: saved-reports service.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::models::{CreateSavedReportRequest, SavedReportResponse, UpdateSavedReportRequest};
use crate::db::Database;
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

/// PMS-683: every query runs inside `Database::begin_with_tenant`, which sets
/// the `app.current_tenant` GUC transaction-locally, so `saved_reports` and
/// `scheduled_reports` are safe under the fail-closed `tenant_isolation` RLS
/// policy (migration 095). `execute` also runs its compiled entity query inside
/// the same GUC transaction, so report execution over RLS-enabled entity tables
/// (e.g. tickets) is scoped correctly. The cross-tenant sweep in
/// ScheduledReportsWorker uses the BYPASSRLS migrator pool.
#[derive(Clone)]
pub struct SavedReportsService {
    db: Database,
}

impl SavedReportsService {
    pub fn new(db: Database) -> Self {
        Self { db }
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q.fetch_all(&mut *tx).await?;
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ReportRow>(&sql)
            .bind(tenant_id)
            .bind(id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound("Saved report".into()))?;
        Ok(row.into())
    }

    pub async fn create(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        req: CreateSavedReportRequest,
    ) -> AppResult<SavedReportResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let owner: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM saved_reports \
             WHERE tenant_id = $1 AND id = $2 AND created_by_id = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        if owner.is_none() {
            return Err(AppError::NotFound("Saved report".into()));
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
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get(tenant_id, user_id, id).await
    }

    pub async fn delete(&self, tenant_id: Uuid, user_id: Uuid, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query(
            "DELETE FROM saved_reports \
             WHERE tenant_id = $1 AND id = $2 AND created_by_id = $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if rows == 0 {
            return Err(AppError::NotFound("Saved report".into()));
        }
        Ok(())
    }

    /// PMS-477: execute a saved report. Loads the row (which already
    /// enforces the per-user visibility rule via `get`), compiles
    /// its definition through the per-entity compiler, runs the SELECT,
    /// and returns rows as JSON maps keyed by the column aliases.
    /// Pagination is overridable per-request so the SPA can page
    /// through a large result set without persisting page/per_page
    /// on the saved-report row.
    pub async fn execute(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
        page: u32,
        per_page: u32,
    ) -> AppResult<ExecuteReportResponse> {
        let report = self.get(tenant_id, user_id, id).await?;
        let limit = per_page.clamp(1, MAX_REPORT_ROWS_PER_PAGE);
        let offset = page.saturating_sub(1).saturating_mul(limit);
        let compiled = super::compiler::compile(
            tenant_id,
            &report.entity_type,
            &report.filters,
            &report.columns,
            &report.sort,
            limit,
            offset,
        )?;

        // PMS-683: the compiled query reads the entity tables (tickets, etc.),
        // which are under fail-closed RLS, so run both statements inside the
        // tenant-GUC transaction. A raw-pool read would return zero rows.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // The count query has the same WHERE binds as the paged
        // SELECT minus the LIMIT/OFFSET pair. Run it first so the
        // SPA's pagination footer renders even on an empty page.
        let mut count_q = sqlx::query_scalar::<_, i64>(&compiled.count_sql);
        for bv in &compiled.count_binds {
            count_q = bind_one_scalar(count_q, bv);
        }
        let total: i64 = count_q.fetch_one(&mut *tx).await?;

        // Materialise the rows as JSON via Postgres `row_to_json` so
        // the per-column type handling lives in the database, not
        // here. The compiler already aliased every SELECT column;
        // wrapping the whole SELECT in a subquery and projecting
        // `row_to_json(s)` yields one `serde_json::Value` per row
        // shaped exactly like the SPA expects.
        let wrapped = format!("SELECT row_to_json(s) AS r FROM ({}) s", compiled.sql);
        let mut row_q = sqlx::query_scalar::<_, serde_json::Value>(&wrapped);
        for bv in &compiled.binds {
            row_q = bind_one_scalar(row_q, bv);
        }
        let rows = row_q.fetch_all(&mut *tx).await?;

        // PMS-690: the SELECT aliases are whitelist-derived column keys,
        // so re-key each row to the operator's display headers here. The
        // wire shape (rows keyed by header) is unchanged.
        let rows: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|r| relabel_row(r, &compiled.columns, &compiled.aliases))
            .collect();

        Ok(ExecuteReportResponse {
            rows,
            total,
            page,
            per_page: limit,
            aliases: compiled.aliases,
        })
    }
}

/// Cap on `per_page` for report execution. Stricter than the
/// existing 100-default pagination cap because a report is a
/// CALLER-CHOSEN column subset across MANY joined tables; pulling
/// the world in one call would blow the connection's memory budget.
/// 10k rows is enough for an executive's quarterly export without
/// asking them to page; anything larger should go through the
/// scheduled-delivery path (PMS-478) which streams to S3 / email.
const MAX_REPORT_ROWS_PER_PAGE: u32 = 10_000;

/// Re-key one `row_to_json` object from the compiler's SQL output
/// names to the display headers, keeping the declared column order.
/// A column the row does not carry lands as null.
fn relabel_row(
    row: serde_json::Value,
    columns: &[String],
    aliases: &[String],
) -> serde_json::Value {
    let Some(obj) = row.as_object() else {
        return row;
    };
    let mut out = serde_json::Map::with_capacity(columns.len());
    for (key, alias) in columns.iter().zip(aliases) {
        out.insert(
            alias.clone(),
            obj.get(key).cloned().unwrap_or(serde_json::Value::Null),
        );
    }
    serde_json::Value::Object(out)
}

/// Bind a `BindValue` onto a `query_scalar` builder. Returned
/// builder is type-identical to its input so the binds can be
/// chained in a loop. Generic over the scalar output so the same
/// helper drives both the COUNT path (`i64`) and the row path
/// (`serde_json::Value`).
fn bind_one_scalar<'q, O>(
    q: sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    bv: &'q super::compiler::BindValue,
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>
where
    O: Send + Unpin + for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    use super::compiler::BindValue::*;
    match bv {
        Uuid(u) => q.bind(*u),
        UuidList(v) => q.bind(v.clone()),
        Text(s) => q.bind(s.clone()),
        TextList(v) => q.bind(v.clone()),
        Int(i) => q.bind(*i),
        Bool(b) => q.bind(*b),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecuteReportResponse {
    /// One JSON object per row, shaped by the alias list. Order of
    /// keys is undefined; consumers should use `aliases` to render
    /// the columns in the saved-report's declared order.
    pub rows: Vec<serde_json::Value>,
    /// Total matching rows across all pages (no LIMIT/OFFSET).
    /// Surfaces the same number the SPA's pagination footer needs.
    pub total: i64,
    /// Echoed back so the SPA can confirm pagination state without
    /// re-deriving from a query string.
    pub page: u32,
    pub per_page: u32,
    /// Ordered alias list the compiler emitted. Lets the SPA render
    /// columns in the order the saved report declares without
    /// relying on JSON-object key order.
    pub aliases: Vec<String>,
}

// PMS-478: schedule machinery ------------------------------------------------

use super::models::{
    CreateScheduledReportRequest, ScheduledReportResponse, UpdateScheduledReportRequest,
};

#[derive(Debug, FromRow)]
struct ScheduleRow {
    id: Uuid,
    saved_report_id: Uuid,
    user_id: Uuid,
    cron_expr: String,
    channel: String,
    format: String,
    recipient_email: Option<String>,
    is_active: bool,
    last_run_at: Option<DateTime<Utc>>,
    next_run_at: DateTime<Utc>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<ScheduleRow> for ScheduledReportResponse {
    fn from(r: ScheduleRow) -> Self {
        Self {
            id: r.id,
            saved_report_id: r.saved_report_id,
            user_id: r.user_id,
            cron_expr: r.cron_expr,
            channel: r.channel,
            format: r.format,
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

const SCHEDULE_SELECT: &str = "
    id, saved_report_id, user_id, cron_expr, channel, format,
    recipient_email, is_active, last_run_at, next_run_at, last_error,
    created_at, updated_at
";

impl SavedReportsService {
    /// PMS-478: create a schedule against a saved report. Reuses the
    /// `get` visibility rule (author OR shared) so a private report
    /// can only be scheduled by its owner. `next_run_at` is computed
    /// from the cron expression with NOW as the anchor; a freshly-
    /// created schedule fires on its first cron tick after creation.
    pub async fn schedule_create(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        saved_report_id: Uuid,
        req: CreateScheduledReportRequest,
    ) -> AppResult<ScheduledReportResponse> {
        // Visibility check via the existing `get`. Surfaces 404 for a
        // private report the caller cannot see, same shape as the
        // SPA's other report endpoints.
        let _ = self.get(tenant_id, user_id, saved_report_id).await?;
        let next_run = compute_next_run(&req.cron_expr, Utc::now())?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO scheduled_reports \
                 (tenant_id, saved_report_id, user_id, cron_expr, \
                  recipient_email, is_active, next_run_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(saved_report_id)
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
        saved_report_id: Uuid,
    ) -> AppResult<Vec<ScheduledReportResponse>> {
        let sql = format!(
            "SELECT {SCHEDULE_SELECT} FROM scheduled_reports \
             WHERE tenant_id = $1 AND saved_report_id = $2 \
             ORDER BY created_at DESC",
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, ScheduleRow>(&sql)
            .bind(tenant_id)
            .bind(saved_report_id)
            .fetch_all(&mut *tx)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn schedule_get(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AppResult<ScheduledReportResponse> {
        let sql = format!(
            "SELECT {SCHEDULE_SELECT} FROM scheduled_reports \
             WHERE tenant_id = $1 AND id = $2",
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ScheduleRow>(&sql)
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound("Scheduled report".into()))?;
        Ok(row.into())
    }

    /// PATCH a schedule. Only the owner may mutate it; another
    /// viewer (who can see the parent shared report) gets 404 - keeps
    /// the response shape uniform with `update` on the parent.
    pub async fn schedule_update(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        id: Uuid,
        req: UpdateScheduledReportRequest,
    ) -> AppResult<ScheduledReportResponse> {
        // Re-compute next_run_at when the cron expression changes;
        // leave it alone otherwise so a Pause -> Resume cycle does
        // not skip ahead in cadence beyond what NOW would produce.
        let new_next: Option<DateTime<Utc>> = match req.cron_expr.as_deref() {
            Some(expr) => Some(compute_next_run(expr, Utc::now())?),
            None => None,
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query(
            "UPDATE scheduled_reports SET \
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
            return Err(AppError::NotFound("Scheduled report".into()));
        }
        self.schedule_get(tenant_id, id).await
    }

    pub async fn schedule_delete(&self, tenant_id: Uuid, user_id: Uuid, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query(
            "DELETE FROM scheduled_reports \
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
            return Err(AppError::NotFound("Scheduled report".into()));
        }
        Ok(())
    }
}

/// PMS-478: parse + advance a cron expression. Returns the next
/// firing instant strictly after `anchor`. Used both on create (anchor
/// = NOW; the first firing happens at the next cron tick after creation)
/// and inside the worker (anchor = `last_run_at` so a backlogged
/// schedule catches up cleanly).
pub(crate) fn compute_next_run(expr: &str, anchor: DateTime<Utc>) -> AppResult<DateTime<Utc>> {
    use std::str::FromStr;
    let schedule = cron::Schedule::from_str(expr)
        .map_err(|e| AppError::BadRequest(format!("Invalid cron expression: {e}")))?;
    schedule
        .after(&anchor)
        .next()
        .ok_or_else(|| AppError::Internal(format!("Cron '{expr}' has no future firings")))
}
