//! Reports service. Read-only aggregates against the production
//! schemas; no business logic of its own beyond the SQL.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Serialize;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct ReportsService {
    db: Database,
}

impl ReportsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Connection pool, for the custom-report builder which constructs its
    /// own dynamic (but fully whitelisted) query. See `super::custom`.
    pub fn pool(&self) -> &sqlx::PgPool {
        self.db.pool()
    }

    // PMS-95 dashboard --------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn dashboard(&self, tenant_id: TenantId) -> AppResult<DashboardResponse> {
        let open_by_priority: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT tp.name, COUNT(*)::bigint
               FROM tickets t
               INNER JOIN ticket_statuses ts ON t.status_id = ts.id
               INNER JOIN ticket_priorities tp ON t.priority_id = tp.id
               WHERE t.tenant_id = $1 AND ts.is_closed = FALSE
               GROUP BY tp.name ORDER BY tp.name"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        let sla_warnings: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM tickets
               WHERE tenant_id = $1 AND sla_due_date < NOW() + INTERVAL '2 hours'
                 AND sla_due_date > NOW() AND closed_at IS NULL"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        let sla_breached: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM tickets
               WHERE tenant_id = $1 AND sla_due_date < NOW() AND closed_at IS NULL"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        let trend: Vec<(NaiveDate, i64)> = sqlx::query_as(
            r#"SELECT (created_at::date) AS d, COUNT(*)::bigint
               FROM tickets WHERE tenant_id = $1
                 AND created_at >= CURRENT_DATE - INTERVAL '30 days'
               GROUP BY d ORDER BY d"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(DashboardResponse {
            open_by_priority: open_by_priority
                .into_iter()
                .map(|(name, count)| Bucket { label: name, count })
                .collect(),
            sla_warnings,
            sla_breached,
            ticket_trend_30d: trend
                .into_iter()
                .map(|(d, count)| DatedCount { date: d, count })
                .collect(),
        })
    }

    // PMS-96 tickets ----------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn tickets(
        &self,
        tenant_id: TenantId,
        from: Option<NaiveDate>,
        to: Option<NaiveDate>,
    ) -> AppResult<TicketsReportResponse> {
        let (from, to) = (
            from.unwrap_or_else(|| chrono::Utc::now().date_naive() - chrono::Duration::days(30)),
            to.unwrap_or_else(|| chrono::Utc::now().date_naive()),
        );
        let opened: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT ts.name, COUNT(*)::bigint
               FROM tickets t INNER JOIN ticket_statuses ts ON t.status_id = ts.id
               WHERE t.tenant_id = $1 AND t.created_at::date BETWEEN $2 AND $3
               GROUP BY ts.name ORDER BY ts.name"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(self.db.pool())
        .await?;
        let closed: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM tickets
               WHERE tenant_id = $1 AND closed_at::date BETWEEN $2 AND $3"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_one(self.db.pool())
        .await?;
        let by_assignee: Vec<(Option<Uuid>, i64)> = sqlx::query_as(
            r#"SELECT assigned_to_id, COUNT(*)::bigint FROM tickets
               WHERE tenant_id = $1 AND created_at::date BETWEEN $2 AND $3
               GROUP BY assigned_to_id"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(self.db.pool())
        .await?;
        Ok(TicketsReportResponse {
            from,
            to,
            opened_by_status: opened
                .into_iter()
                .map(|(name, c)| Bucket {
                    label: name,
                    count: c,
                })
                .collect(),
            closed_total: closed,
            opened_by_assignee: by_assignee
                .into_iter()
                .map(|(uid, c)| AssigneeCount {
                    assignee_id: uid,
                    count: c,
                })
                .collect(),
        })
    }

    // PMS-97 time -------------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn time(
        &self,
        tenant_id: TenantId,
        from: Option<NaiveDate>,
        to: Option<NaiveDate>,
    ) -> AppResult<TimeReportResponse> {
        let (from, to) = (
            from.unwrap_or_else(|| chrono::Utc::now().date_naive() - chrono::Duration::days(30)),
            to.unwrap_or_else(|| chrono::Utc::now().date_naive()),
        );
        let by_user: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"SELECT user_id, SUM(duration_minutes)::bigint FROM time_entries
               WHERE tenant_id = $1 AND date BETWEEN $2 AND $3
               GROUP BY user_id"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(self.db.pool())
        .await?;
        let by_work_type: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"SELECT work_type_id, SUM(duration_minutes)::bigint FROM time_entries
               WHERE tenant_id = $1 AND date BETWEEN $2 AND $3
               GROUP BY work_type_id"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(self.db.pool())
        .await?;
        Ok(TimeReportResponse {
            from,
            to,
            minutes_by_user: by_user
                .into_iter()
                .map(|(id, m)| IdCount { id, count: m })
                .collect(),
            minutes_by_work_type: by_work_type
                .into_iter()
                .map(|(id, m)| IdCount { id, count: m })
                .collect(),
        })
    }

    // PMS-98 billing ----------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn billing(
        &self,
        tenant_id: TenantId,
        company_id: Option<Uuid>,
    ) -> AppResult<BillingReportResponse> {
        let totals: Option<(Decimal, Decimal, Decimal)> = if let Some(c) = company_id {
            sqlx::query_as(
                r#"SELECT COALESCE(SUM(total), 0), COALESCE(SUM(amount_paid), 0),
                          COALESCE(SUM(balance_due), 0)
                   FROM invoices WHERE tenant_id = $1 AND company_id = $2"#,
            )
            .bind(tenant_id)
            .bind(c)
            .fetch_optional(self.db.pool())
            .await?
        } else {
            sqlx::query_as(
                r#"SELECT COALESCE(SUM(total), 0), COALESCE(SUM(amount_paid), 0),
                          COALESCE(SUM(balance_due), 0)
                   FROM invoices WHERE tenant_id = $1"#,
            )
            .bind(tenant_id)
            .fetch_optional(self.db.pool())
            .await?
        };
        let (invoiced, paid, outstanding) =
            totals.unwrap_or((Decimal::ZERO, Decimal::ZERO, Decimal::ZERO));

        let aging: Vec<(String, Decimal)> = sqlx::query_as(
            r#"SELECT
                  CASE
                    WHEN due_date >= CURRENT_DATE THEN 'current'
                    WHEN CURRENT_DATE - due_date <= 30 THEN '1-30'
                    WHEN CURRENT_DATE - due_date <= 60 THEN '31-60'
                    WHEN CURRENT_DATE - due_date <= 90 THEN '61-90'
                    ELSE '90+'
                  END AS bucket,
                  SUM(balance_due) AS total
               FROM invoices
               WHERE tenant_id = $1 AND balance_due > 0
                 AND ($2::uuid IS NULL OR company_id = $2)
               GROUP BY bucket"#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(BillingReportResponse {
            invoiced,
            paid,
            outstanding,
            aging: aging
                .into_iter()
                .map(|(bucket, total)| AgingBucket { bucket, total })
                .collect(),
        })
    }

    // PMS-179 projects --------------------------------------------------------
    /// Project delivery: counts by status, budget vs actual (actuals come
    /// from `time_entries` linked to a project), task completion, and
    /// overdue projects. Powers the SPA project-status / budget-tracking /
    /// milestone-tracking report types.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn projects(&self, tenant_id: TenantId) -> AppResult<ProjectsReportResponse> {
        let by_status: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT status, COUNT(*)::bigint
               FROM projects WHERE tenant_id = $1
               GROUP BY status ORDER BY status"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        let (budget_hours, budget_amount): (Decimal, Decimal) = sqlx::query_as(
            r#"SELECT COALESCE(SUM(budget_hours), 0), COALESCE(SUM(budget_amount), 0)
               FROM projects WHERE tenant_id = $1"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        // Actuals: only time entries that belong to a project count toward a
        // project's spend. Minutes are summed in SQL; hours are derived once
        // here so callers and CSV share the same rounding.
        let (actual_minutes, actual_amount): (i64, Decimal) = sqlx::query_as(
            r#"SELECT COALESCE(SUM(duration_minutes), 0)::bigint,
                      COALESCE(SUM(total_amount), 0)
               FROM time_entries
               WHERE tenant_id = $1 AND project_id IS NOT NULL"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;
        let actual_hours = Decimal::from(actual_minutes) / Decimal::from(60);

        let (tasks_total, tasks_completed): (i64, i64) = sqlx::query_as(
            r#"SELECT COUNT(*)::bigint,
                      COUNT(*) FILTER (WHERE tst.is_completed)::bigint
               FROM tasks t
               INNER JOIN task_statuses tst ON t.status_id = tst.id
               WHERE t.tenant_id = $1"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        let overdue: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM projects
               WHERE tenant_id = $1 AND target_end_date < CURRENT_DATE
                 AND status NOT IN ('completed', 'cancelled')"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        Ok(ProjectsReportResponse {
            by_status: by_status
                .into_iter()
                .map(|(label, count)| Bucket { label, count })
                .collect(),
            budget_hours,
            budget_amount,
            actual_hours,
            actual_amount,
            tasks_total,
            tasks_completed,
            overdue,
        })
    }

    // PMS-179 clients ---------------------------------------------------------
    /// Client / CMDB summary: company counts, asset inventory by type and
    /// status, warranties expiring soon, and contract renewals. Powers the
    /// SPA client-summary / asset-inventory / contract-renewals report types.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn clients(&self, tenant_id: TenantId) -> AppResult<ClientsReportResponse> {
        let (companies_total, companies_active): (i64, i64) = sqlx::query_as(
            r#"SELECT COUNT(*)::bigint,
                      COUNT(*) FILTER (WHERE status = 'active')::bigint
               FROM companies WHERE tenant_id = $1"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        let assets_total: i64 =
            sqlx::query_scalar(r#"SELECT COUNT(*)::bigint FROM assets WHERE tenant_id = $1"#)
                .bind(tenant_id)
                .fetch_one(self.db.pool())
                .await?;

        let by_type: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT at.name, COUNT(*)::bigint
               FROM assets a INNER JOIN asset_types at ON a.asset_type_id = at.id
               WHERE a.tenant_id = $1
               GROUP BY at.name ORDER BY at.name"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        let by_status: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT status, COUNT(*)::bigint
               FROM assets WHERE tenant_id = $1
               GROUP BY status ORDER BY status"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        let warranty_expiring_90d: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM assets
               WHERE tenant_id = $1
                 AND warranty_expiry BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '90 days'"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        let (contracts_active, contracts_renewing_90d): (i64, i64) = sqlx::query_as(
            r#"SELECT
                  COUNT(*) FILTER (WHERE status = 'active')::bigint,
                  COUNT(*) FILTER (
                      WHERE status = 'active' AND end_date IS NOT NULL
                        AND end_date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '90 days'
                  )::bigint
               FROM contracts WHERE tenant_id = $1"#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        Ok(ClientsReportResponse {
            companies_total,
            companies_active,
            assets_total,
            assets_by_type: by_type
                .into_iter()
                .map(|(label, count)| Bucket { label, count })
                .collect(),
            assets_by_status: by_status
                .into_iter()
                .map(|(label, count)| Bucket { label, count })
                .collect(),
            warranty_expiring_90d,
            contracts_active,
            contracts_renewing_90d,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Bucket {
    pub label: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatedCount {
    pub date: NaiveDate,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssigneeCount {
    pub assignee_id: Option<Uuid>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdCount {
    pub id: Uuid,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgingBucket {
    pub bucket: String,
    pub total: Decimal,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardResponse {
    pub open_by_priority: Vec<Bucket>,
    pub sla_warnings: i64,
    pub sla_breached: i64,
    pub ticket_trend_30d: Vec<DatedCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TicketsReportResponse {
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub opened_by_status: Vec<Bucket>,
    pub closed_total: i64,
    pub opened_by_assignee: Vec<AssigneeCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeReportResponse {
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub minutes_by_user: Vec<IdCount>,
    pub minutes_by_work_type: Vec<IdCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BillingReportResponse {
    pub invoiced: Decimal,
    pub paid: Decimal,
    pub outstanding: Decimal,
    pub aging: Vec<AgingBucket>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectsReportResponse {
    pub by_status: Vec<Bucket>,
    pub budget_hours: Decimal,
    pub budget_amount: Decimal,
    pub actual_hours: Decimal,
    pub actual_amount: Decimal,
    pub tasks_total: i64,
    pub tasks_completed: i64,
    pub overdue: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientsReportResponse {
    pub companies_total: i64,
    pub companies_active: i64,
    pub assets_total: i64,
    pub assets_by_type: Vec<Bucket>,
    pub assets_by_status: Vec<Bucket>,
    pub warranty_expiring_90d: i64,
    pub contracts_active: i64,
    pub contracts_renewing_90d: i64,
}
