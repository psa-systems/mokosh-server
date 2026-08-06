//! Reports service. Read-only aggregates against the production
//! schemas; no business logic of its own beyond the SQL.

use chrono::{Datelike, NaiveDate};
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

    /// Run a whitelisted custom report inside a tenant-scoped transaction
    /// so the dynamic (but fully whitelisted) query carries the RLS
    /// `app.current_tenant` GUC (PMS-256). Read-only: the tx is dropped
    /// (rolled back) after the SELECT. See `super::custom`.
    pub async fn run_custom(
        &self,
        tenant_id: TenantId,
        spec: &super::custom::CustomSpec,
    ) -> AppResult<super::custom::CustomReportResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        super::custom::run(&mut *tx, tenant_id, spec).await
    }

    // PMS-95 dashboard --------------------------------------------------------
    /// `user_tz` is the active user's `users.timezone` preference (PMS-253).
    /// The 30-day ticket trend is the one server-computed per-day bucket on a
    /// `timestamptz`, so it must group by the user's local day rather than the
    /// UTC day (PMS-360); otherwise a ticket created at 23:30 Pacific lands in
    /// tomorrow's UTC bar and the chart disagrees with every other "today"
    /// surface.
    ///
    /// PMS-406: `team_id`, when `Some`, scopes every aggregate to a single
    /// team via a parameterized `AND ... team_id = $n`, so the full-screen
    /// TV-view dashboard can request a team-scoped KPI set. The tenant
    /// predicate stays the unconditional first condition; team scoping is
    /// strictly additive. Absent the param, output is unchanged (tenant
    /// only). A cross-tenant team id is harmless here: every query is
    /// already tenant-scoped, so a foreign team matches no rows and yields
    /// zeros rather than leaking another tenant's data.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn dashboard(
        &self,
        tenant_id: TenantId,
        team_id: Option<Uuid>,
        user_tz: &str,
    ) -> AppResult<DashboardResponse> {
        let tz_name = mokosh_types::datetime::canonical_tz_name(user_tz);
        // Anchor the 30-day window to "today" in the user's zone, computed in
        // Rust so the bound and the SQL bucket agree on which zone they mean.
        let window_start = mokosh_types::datetime::user_today(chrono::Utc::now(), user_tz)
            - chrono::Duration::days(30);
        // Optional team-scope fragment. `qualifier` is the column prefix
        // (`t.` where the query aliases tickets, empty otherwise); `idx` is
        // the next free placeholder for each query. Empty string when no
        // team is requested, so the base queries are byte-for-byte unchanged.
        let team_clause = |qualifier: &str, idx: usize| -> String {
            match team_id {
                Some(_) => format!(" AND {qualifier}team_id = ${idx}"),
                None => String::new(),
            }
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let open_sql = format!(
            r#"SELECT tp.name, COUNT(*)::bigint
               FROM tickets t
               INNER JOIN ticket_statuses ts ON t.status_id = ts.id
               INNER JOIN ticket_priorities tp ON t.priority_id = tp.id
               WHERE t.tenant_id = $1 AND ts.is_closed = FALSE{team}
               GROUP BY tp.name ORDER BY tp.name"#,
            team = team_clause("t.", 2),
        );
        let mut open_q = sqlx::query_as::<_, (String, i64)>(&open_sql).bind(tenant_id);
        if let Some(team_id) = team_id {
            open_q = open_q.bind(team_id);
        }
        let open_by_priority: Vec<(String, i64)> = open_q.fetch_all(&mut *tx).await?;

        let warn_sql = format!(
            r#"SELECT COUNT(*)::bigint FROM tickets
               WHERE tenant_id = $1 AND sla_due_date < NOW() + INTERVAL '2 hours'
                 AND sla_due_date > NOW() AND closed_at IS NULL{team}"#,
            team = team_clause("", 2),
        );
        let mut warn_q = sqlx::query_scalar::<_, i64>(&warn_sql).bind(tenant_id);
        if let Some(team_id) = team_id {
            warn_q = warn_q.bind(team_id);
        }
        let sla_warnings: i64 = warn_q.fetch_one(&mut *tx).await?;

        let breach_sql = format!(
            r#"SELECT COUNT(*)::bigint FROM tickets
               WHERE tenant_id = $1 AND sla_due_date < NOW() AND closed_at IS NULL{team}"#,
            team = team_clause("", 2),
        );
        let mut breach_q = sqlx::query_scalar::<_, i64>(&breach_sql).bind(tenant_id);
        if let Some(team_id) = team_id {
            breach_q = breach_q.bind(team_id);
        }
        let sla_breached: i64 = breach_q.fetch_one(&mut *tx).await?;

        let trend_sql = format!(
            r#"SELECT ((created_at AT TIME ZONE $2)::date) AS d, COUNT(*)::bigint
               FROM tickets WHERE tenant_id = $1
                 AND (created_at AT TIME ZONE $2)::date >= $3{team}
               GROUP BY d ORDER BY d"#,
            team = team_clause("", 4),
        );
        let mut trend_q = sqlx::query_as::<_, (NaiveDate, i64)>(&trend_sql)
            .bind(tenant_id)
            .bind(tz_name)
            .bind(window_start);
        if let Some(team_id) = team_id {
            trend_q = trend_q.bind(team_id);
        }
        let trend: Vec<(NaiveDate, i64)> = trend_q.fetch_all(&mut *tx).await?;

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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let opened: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT ts.name, COUNT(*)::bigint
               FROM tickets t INNER JOIN ticket_statuses ts ON t.status_id = ts.id
               WHERE t.tenant_id = $1 AND t.created_at::date BETWEEN $2 AND $3
               GROUP BY ts.name ORDER BY ts.name"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(&mut *tx)
        .await?;
        let closed: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM tickets
               WHERE tenant_id = $1 AND closed_at::date BETWEEN $2 AND $3"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_one(&mut *tx)
        .await?;
        let by_assignee: Vec<(Option<Uuid>, i64)> = sqlx::query_as(
            r#"SELECT assigned_to_id, COUNT(*)::bigint FROM tickets
               WHERE tenant_id = $1 AND created_at::date BETWEEN $2 AND $3
               GROUP BY assigned_to_id"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(&mut *tx)
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let by_user: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"SELECT user_id, SUM(duration_minutes)::bigint FROM time_entries
               WHERE tenant_id = $1 AND date BETWEEN $2 AND $3
               GROUP BY user_id"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(&mut *tx)
        .await?;
        let by_work_type: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"SELECT work_type_id, SUM(duration_minutes)::bigint FROM time_entries
               WHERE tenant_id = $1 AND date BETWEEN $2 AND $3
               GROUP BY work_type_id"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(&mut *tx)
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let totals: Option<(Decimal, Decimal, Decimal)> = if let Some(c) = company_id {
            sqlx::query_as(
                r#"SELECT COALESCE(SUM(total), 0), COALESCE(SUM(amount_paid), 0),
                          COALESCE(SUM(balance_due), 0)
                   FROM invoices WHERE tenant_id = $1 AND company_id = $2"#,
            )
            .bind(tenant_id)
            .bind(c)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            sqlx::query_as(
                r#"SELECT COALESCE(SUM(total), 0), COALESCE(SUM(amount_paid), 0),
                          COALESCE(SUM(balance_due), 0)
                   FROM invoices WHERE tenant_id = $1"#,
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
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
        .fetch_all(&mut *tx)
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let grouped: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT status, COUNT(*)::bigint
               FROM projects WHERE tenant_id = $1
               GROUP BY status ORDER BY status"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;

        // PMS-366: GROUP BY only emits statuses that have rows, so a tenant
        // with no Planning or Cancelled projects loses those buckets and the
        // dashboard counters silently omit those states. A brand-new project
        // (born "planning", since the create form has no status field) then
        // counts toward nothing. Zero-fill every canonical project status -
        // the exact set the `projects.status` CHECK constraint allows - so all
        // five states are always countable from the server; the sum across
        // buckets still equals the total project rows. Any non-canonical
        // status that somehow appears is preserved, appended (sorted) after
        // the canonical five so the totals still reconcile.
        const CANONICAL_PROJECT_STATUSES: [&str; 5] =
            ["planning", "active", "on_hold", "completed", "cancelled"];
        let mut counts: std::collections::HashMap<String, i64> = grouped.into_iter().collect();
        let mut by_status: Vec<Bucket> = CANONICAL_PROJECT_STATUSES
            .iter()
            .map(|&label| Bucket {
                label: label.to_string(),
                count: counts.remove(label).unwrap_or(0),
            })
            .collect();
        let mut extra: Vec<Bucket> = counts
            .into_iter()
            .map(|(label, count)| Bucket { label, count })
            .collect();
        extra.sort_by(|a, b| a.label.cmp(&b.label));
        by_status.append(&mut extra);

        let (budget_hours, budget_amount): (Decimal, Decimal) = sqlx::query_as(
            r#"SELECT COALESCE(SUM(budget_hours), 0), COALESCE(SUM(budget_amount), 0)
               FROM projects WHERE tenant_id = $1"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
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
        .fetch_one(&mut *tx)
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
        .fetch_one(&mut *tx)
        .await?;

        let overdue: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM projects
               WHERE tenant_id = $1 AND target_end_date < CURRENT_DATE
                 AND status NOT IN ('completed', 'cancelled')"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;

        Ok(ProjectsReportResponse {
            by_status,
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let (companies_total, companies_active): (i64, i64) = sqlx::query_as(
            r#"SELECT COUNT(*)::bigint,
                      COUNT(*) FILTER (WHERE status = 'active')::bigint
               FROM companies WHERE tenant_id = $1 AND company_type <> 'internal'"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;

        let assets_total: i64 =
            sqlx::query_scalar(r#"SELECT COUNT(*)::bigint FROM assets WHERE tenant_id = $1"#)
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let by_type: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT at.name, COUNT(*)::bigint
               FROM assets a INNER JOIN asset_types at ON a.asset_type_id = at.id
               WHERE a.tenant_id = $1
               GROUP BY at.name ORDER BY at.name"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;

        let grouped: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT status, COUNT(*)::bigint
               FROM assets WHERE tenant_id = $1
               GROUP BY status ORDER BY status"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;

        // PMS-366: same zero-omission gap as the projects counter above. Asset
        // state has a fixed `assets.status` CHECK set; zero-fill it so every
        // state is always countable and the buckets sum to the asset total.
        const CANONICAL_ASSET_STATUSES: [&str; 5] =
            ["active", "inactive", "retired", "in_repair", "in_stock"];
        let mut counts: std::collections::HashMap<String, i64> = grouped.into_iter().collect();
        let mut by_status: Vec<Bucket> = CANONICAL_ASSET_STATUSES
            .iter()
            .map(|&label| Bucket {
                label: label.to_string(),
                count: counts.remove(label).unwrap_or(0),
            })
            .collect();
        let mut extra: Vec<Bucket> = counts
            .into_iter()
            .map(|(label, count)| Bucket { label, count })
            .collect();
        extra.sort_by(|a, b| a.label.cmp(&b.label));
        by_status.append(&mut extra);

        let warranty_expiring_90d: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM assets
               WHERE tenant_id = $1
                 AND warranty_expiry BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '90 days'"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
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
        .fetch_one(&mut *tx)
        .await?;

        Ok(ClientsReportResponse {
            companies_total,
            companies_active,
            assets_total,
            assets_by_type: by_type
                .into_iter()
                .map(|(label, count)| Bucket { label, count })
                .collect(),
            assets_by_status: by_status,
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

// ============================================================================
// PMS-732: REQUEST-TYPE DURATIONS
// ============================================================================

/// Measured duration for one request type over a period.
///
/// `total_minutes`, `ticket_count` and `average_minutes` are `Option` on
/// purpose. A request type with no recorded time in the period reports NULL,
/// not zero: zero minutes is a measurement ("we did these and they took no
/// time"), while no data is the absence of one, and the whole point of this
/// report is to replace hand-written guesses with measurements. Collapsing the
/// two would put a confident "0 min" estimate on an article nobody has ever
/// tracked time against.
#[derive(Debug, Clone, Serialize)]
pub struct RequestTypeDuration {
    pub form_definition_id: Uuid,
    pub form_name: String,
    pub form_slug: String,
    pub kb_article_id: Option<Uuid>,
    pub kb_article_title: Option<String>,
    /// Tickets from this request type with at least one time entry in the
    /// period. This is the sample the average is drawn from, not the number of
    /// requests received.
    pub ticket_count: Option<i64>,
    pub total_minutes: Option<i64>,
    pub average_minutes: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestTypeDurationsResponse {
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub request_types: Vec<RequestTypeDuration>,
}

#[derive(sqlx::FromRow)]
struct RequestTypeDurationRow {
    form_definition_id: Uuid,
    form_name: String,
    form_slug: String,
    kb_article_id: Option<Uuid>,
    kb_article_title: Option<String>,
    ticket_count: i64,
    total_minutes: Option<i64>,
}

/// First day of the calendar month containing `today`.
pub(crate) fn month_start(today: NaiveDate) -> NaiveDate {
    today.with_day(1).unwrap_or(today)
}

impl ReportsService {
    /// Time tracked against tickets that came from a client request
    /// submission, grouped by the request type that produced them.
    ///
    /// The join walks time_entries -> tickets -> form_submissions ->
    /// form_definitions, so ONLY tickets created from a submission are
    /// counted. An ad-hoc ticket in the same category never entered a request
    /// form, has no submission row, and is excluded, which is what keeps the
    /// measurement about the request type rather than about the category.
    ///
    /// Every request type is returned, including ones with no tracked time, so
    /// the caller can tell "no data" apart from "not a request type".
    ///
    /// Default period is the current calendar month, per PMS-732. Note this
    /// differs from `/reports/time`, which defaults to a trailing 30 days;
    /// worth reconciling if the inconsistency bites.
    pub async fn request_type_durations(
        &self,
        tenant_id: TenantId,
        from: Option<NaiveDate>,
        to: Option<NaiveDate>,
    ) -> AppResult<RequestTypeDurationsResponse> {
        let today = chrono::Utc::now().date_naive();
        let (from, to) = (
            from.unwrap_or_else(|| month_start(today)),
            to.unwrap_or(today),
        );

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, RequestTypeDurationRow>(
            r#"SELECT d.id                          AS form_definition_id,
                      d.name                        AS form_name,
                      d.slug                        AS form_slug,
                      d.kb_article_id,
                      a.title                       AS kb_article_title,
                      COUNT(DISTINCT te.ticket_id)  AS ticket_count,
                      SUM(te.duration_minutes)::bigint AS total_minutes
               FROM form_definitions d
               LEFT JOIN kb_articles a
                      ON a.id = d.kb_article_id AND a.tenant_id = d.tenant_id
               LEFT JOIN form_submissions s
                      ON s.form_definition_id = d.id
                     AND s.tenant_id = d.tenant_id
                     AND s.ticket_id IS NOT NULL
               LEFT JOIN time_entries te
                      ON te.ticket_id = s.ticket_id
                     AND te.tenant_id = d.tenant_id
                     AND te.date BETWEEN $2 AND $3
               WHERE d.tenant_id = $1
               GROUP BY d.id, d.name, d.slug, d.kb_article_id, a.title
               ORDER BY d.name ASC"#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let request_types = rows
            .into_iter()
            .map(|r| {
                // COUNT over an all-NULL outer join is 0, and SUM is NULL.
                // Both collapse to "no data" rather than a zero measurement.
                let has_data = r.ticket_count > 0 && r.total_minutes.is_some();
                RequestTypeDuration {
                    form_definition_id: r.form_definition_id,
                    form_name: r.form_name,
                    form_slug: r.form_slug,
                    kb_article_id: r.kb_article_id,
                    kb_article_title: r.kb_article_title,
                    ticket_count: has_data.then_some(r.ticket_count),
                    total_minutes: has_data.then(|| r.total_minutes.unwrap_or(0)),
                    average_minutes: has_data
                        .then(|| r.total_minutes.unwrap_or(0) as f64 / r.ticket_count as f64),
                }
            })
            .collect();

        Ok(RequestTypeDurationsResponse {
            from,
            to,
            request_types,
        })
    }
}
