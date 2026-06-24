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

        // The count query has the same WHERE binds as the paged
        // SELECT minus the LIMIT/OFFSET pair. Run it first so the
        // SPA's pagination footer renders even on an empty page.
        let mut count_q = sqlx::query_scalar::<_, i64>(&compiled.count_sql);
        for bv in &compiled.count_binds {
            count_q = bind_one_scalar(count_q, bv);
        }
        let total: i64 = count_q.fetch_one(&self.pool).await?;

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
        let rows = row_q.fetch_all(&self.pool).await?;

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
