//! Reports HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::custom;
use super::service::*;
use crate::modules::auth::{RequireFinance, RequireReports, TenantScoped};
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct ReportsRouterState {
    pub service: Arc<ReportsService>,
}

/// One parameter a report accepts.
#[derive(Serialize)]
struct ParamSpec {
    name: &'static str,
    /// `date` | `uuid`
    kind: &'static str,
    required: bool,
}

/// A discoverable report type and its parameter schema (PMS-93 AC1).
#[derive(Serialize)]
struct ReportDescriptor {
    key: &'static str,
    name: &'static str,
    description: &'static str,
    parameters: Vec<ParamSpec>,
}

pub fn reports_routes(service: ReportsService) -> Router {
    let state = ReportsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/reports", get(list_reports))
        .route("/reports/dashboard", get(dashboard))
        .route("/reports/tickets", get(tickets_report))
        .route("/reports/time", get(time_report))
        .route("/reports/billing", get(billing_report))
        .route("/reports/projects", get(projects_report))
        .route("/reports/clients", get(clients_report))
        .route("/reports/custom/schema", get(custom_schema))
        .route("/reports/custom", post(custom_run))
        .route("/reports/{report}/export", get(export_report))
        .with_state(state)
}

#[derive(Deserialize)]
struct DateRange {
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
}

/// Registry of available report types and their parameter schemas, so a
/// client can discover what it can run (PMS-93 AC1).
async fn list_reports(
    RequireReports { .. }: RequireReports,
) -> AppResult<Json<Vec<ReportDescriptor>>> {
    let date = |name, required| ParamSpec {
        name,
        kind: "date",
        required,
    };
    Ok(Json(vec![
        ReportDescriptor {
            key: "dashboard",
            name: "Operations Dashboard",
            description:
                "Open tickets by priority, SLA at-risk / breached, and the 30-day ticket trend.",
            parameters: vec![],
        },
        ReportDescriptor {
            key: "tickets",
            name: "Ticket Volume & SLA",
            description:
                "Tickets opened by status, total closed, and opened-by-assignee for a date range.",
            parameters: vec![date("from", false), date("to", false)],
        },
        ReportDescriptor {
            key: "time",
            name: "Technician Utilization",
            description: "Logged minutes by user and by work type for a date range.",
            parameters: vec![date("from", false), date("to", false)],
        },
        ReportDescriptor {
            key: "billing",
            name: "Revenue & A/R Aging",
            description:
                "Invoiced / paid / outstanding totals and A/R aging buckets. Finance only.",
            parameters: vec![ParamSpec {
                name: "company_id",
                kind: "uuid",
                required: false,
            }],
        },
        ReportDescriptor {
            key: "custom",
            name: "Custom Report Builder",
            description:
                "Build a report from a whitelisted catalog of sources, dimensions, and measures. Discover the catalog at GET /reports/custom/schema and run via POST /reports/custom.",
            parameters: vec![],
        },
        ReportDescriptor {
            key: "projects",
            name: "Project Delivery",
            description:
                "Projects by status, budget vs actual hours / amount, task completion, and overdue projects.",
            parameters: vec![],
        },
        ReportDescriptor {
            key: "clients",
            name: "Clients & Assets",
            description:
                "Company counts, asset inventory by type and status, warranties expiring soon, and contract renewals.",
            parameters: vec![],
        },
    ]))
}

/// PMS-406: `team_id` scopes the dashboard aggregates to a single team so
/// the full-screen TV-view dashboard can request a team-scoped KPI set.
#[derive(Deserialize)]
struct DashboardQ {
    team_id: Option<Uuid>,
}

async fn dashboard(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    Query(q): Query<DashboardQ>,
) -> AppResult<Json<DashboardResponse>> {
    Ok(Json(
        s.service
            .dashboard(u.tenant(), q.team_id, &u.timezone)
            .await?,
    ))
}

async fn tickets_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    Query(q): Query<DateRange>,
) -> AppResult<Json<TicketsReportResponse>> {
    Ok(Json(s.service.tickets(u.tenant(), q.from, q.to).await?))
}

async fn time_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    Query(q): Query<DateRange>,
) -> AppResult<Json<TimeReportResponse>> {
    Ok(Json(s.service.time(u.tenant(), q.from, q.to).await?))
}

#[derive(Deserialize)]
struct BillingQ {
    company_id: Option<Uuid>,
}

async fn billing_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    _f: RequireFinance,
    Query(q): Query<BillingQ>,
) -> AppResult<Json<BillingReportResponse>> {
    Ok(Json(s.service.billing(u.tenant(), q.company_id).await?))
}

async fn projects_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
) -> AppResult<Json<ProjectsReportResponse>> {
    Ok(Json(s.service.projects(u.tenant()).await?))
}

async fn clients_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    // PMS-350: the clients report is Client Profitability - it sums
    // invoiced / paid / outstanding from the invoices table, so it carries
    // the same financial data as the Invoices page and the billing report.
    // Gate it behind the same finance check rather than letting any
    // reports-enabled role (e.g. technician) read company financials.
    _f: RequireFinance,
) -> AppResult<Json<ClientsReportResponse>> {
    Ok(Json(s.service.clients(u.tenant()).await?))
}

/// Catalog the custom-report builder draws from (PMS-180): sources and
/// their whitelisted dimensions / measures / filters.
async fn custom_schema(
    RequireReports { .. }: RequireReports,
) -> AppResult<Json<Vec<custom::SourceSchema>>> {
    Ok(Json(custom::schema()))
}

/// Run a whitelisted custom report. Returns the generic columns / rows /
/// totals envelope as JSON, or CSV when the spec sets `"format": "csv"`.
async fn custom_run(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    Json(spec): Json<custom::CustomSpec>,
) -> AppResult<Response> {
    let report = s.service.run_custom(u.tenant(), &spec).await?;
    if spec.format.as_deref() == Some("csv") {
        let csv = custom::to_csv(&report);
        return Ok((
            [(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")],
            csv,
        )
            .into_response());
    }
    Ok(Json(report).into_response())
}

#[derive(Deserialize)]
struct ExportQ {
    #[serde(default = "default_csv")]
    format: String,
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
    company_id: Option<Uuid>,
    /// PMS-406: team-scope the dashboard export, mirroring the JSON route.
    team_id: Option<Uuid>,
}

fn default_csv() -> String {
    "csv".into()
}

/// Generic export. `:report` selects which report to serialise; today
/// only `csv` is implemented. `pdf` returns 501 with a Retry-After-ish
/// note pointing at the PMS-99 follow-up that wires `printpdf`; we
/// don't pull a wkhtmltopdf binary just for a hint that the format is
/// coming.
async fn export_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    Path(report): Path<String>,
    Query(q): Query<ExportQ>,
) -> AppResult<Response> {
    if !q.format.eq_ignore_ascii_case("csv") {
        return Err(AppError::BadRequest(format!(
            "format {:?} not yet supported; only 'csv' is implemented",
            q.format
        )));
    }
    let csv = match report.as_str() {
        "dashboard" => csv_for_dashboard(
            &s.service
                .dashboard(u.tenant(), q.team_id, &u.timezone)
                .await?,
        ),
        "tickets" => csv_for_tickets(&s.service.tickets(u.tenant(), q.from, q.to).await?),
        "time" => csv_for_time(&s.service.time(u.tenant(), q.from, q.to).await?),
        "billing" => {
            // The billing export carries the same revenue / A/R figures as
            // GET /reports/billing, so it enforces the same finance gate
            // rather than letting any reports-enabled role read it (PMS-350:
            // closing the export side-door around the financial report gate).
            if !u.role.can_manage_billing() {
                return Err(AppError::Forbidden("Insufficient permissions".to_string()));
            }
            csv_for_billing(&s.service.billing(u.tenant(), q.company_id).await?)
        }
        "projects" => csv_for_projects(&s.service.projects(u.tenant()).await?),
        "clients" => {
            // The clients export is Client Profitability (invoiced / paid /
            // outstanding), the same financial data as GET /reports/clients,
            // so it enforces the same finance gate as the billing export above
            // rather than leaving a CSV side-door open (PMS-350).
            if !u.role.can_manage_billing() {
                return Err(AppError::Forbidden("Insufficient permissions".to_string()));
            }
            csv_for_clients(&s.service.clients(u.tenant()).await?)
        }
        other => return Err(AppError::NotFound(format!("report {other:?}"))),
    };
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")],
        csv,
    )
        .into_response())
}

fn csv_for_dashboard(r: &DashboardResponse) -> String {
    let mut s = String::from("priority,open_count\n");
    for b in &r.open_by_priority {
        s.push_str(&format!("{},{}\n", b.label, b.count));
    }
    s.push_str(&format!("\nsla_warnings,{}\n", r.sla_warnings));
    s.push_str(&format!("sla_breached,{}\n", r.sla_breached));
    s.push_str("\ndate,opened\n");
    for d in &r.ticket_trend_30d {
        s.push_str(&format!("{},{}\n", d.date, d.count));
    }
    s
}

fn csv_for_tickets(r: &TicketsReportResponse) -> String {
    let mut s = format!("from,to\n{},{}\n\nstatus,opened\n", r.from, r.to);
    for b in &r.opened_by_status {
        s.push_str(&format!("{},{}\n", b.label, b.count));
    }
    s.push_str(&format!(
        "\nclosed_total,{}\n\nassignee_id,opened\n",
        r.closed_total
    ));
    for a in &r.opened_by_assignee {
        s.push_str(&format!(
            "{},{}\n",
            a.assignee_id
                .map(|u| u.to_string())
                .unwrap_or_else(|| "unassigned".into()),
            a.count,
        ));
    }
    s
}

fn csv_for_time(r: &TimeReportResponse) -> String {
    let mut s = format!("from,to\n{},{}\n\nuser_id,minutes\n", r.from, r.to);
    for i in &r.minutes_by_user {
        s.push_str(&format!("{},{}\n", i.id, i.count));
    }
    s.push_str("\nwork_type_id,minutes\n");
    for i in &r.minutes_by_work_type {
        s.push_str(&format!("{},{}\n", i.id, i.count));
    }
    s
}

fn csv_for_billing(r: &BillingReportResponse) -> String {
    let mut s = String::from("metric,amount\n");
    s.push_str(&format!("invoiced,{}\n", r.invoiced));
    s.push_str(&format!("paid,{}\n", r.paid));
    s.push_str(&format!("outstanding,{}\n", r.outstanding));
    s.push_str("\nbucket,total\n");
    for b in &r.aging {
        s.push_str(&format!("{},{}\n", b.bucket, b.total));
    }
    s
}

fn csv_for_projects(r: &ProjectsReportResponse) -> String {
    let mut s = String::from("status,count\n");
    for b in &r.by_status {
        s.push_str(&format!("{},{}\n", b.label, b.count));
    }
    s.push_str("\nmetric,value\n");
    s.push_str(&format!("budget_hours,{}\n", r.budget_hours));
    s.push_str(&format!("budget_amount,{}\n", r.budget_amount));
    s.push_str(&format!("actual_hours,{}\n", r.actual_hours));
    s.push_str(&format!("actual_amount,{}\n", r.actual_amount));
    s.push_str(&format!("tasks_total,{}\n", r.tasks_total));
    s.push_str(&format!("tasks_completed,{}\n", r.tasks_completed));
    s.push_str(&format!("overdue,{}\n", r.overdue));
    s
}

fn csv_for_clients(r: &ClientsReportResponse) -> String {
    let mut s = String::from("metric,value\n");
    s.push_str(&format!("companies_total,{}\n", r.companies_total));
    s.push_str(&format!("companies_active,{}\n", r.companies_active));
    s.push_str(&format!("assets_total,{}\n", r.assets_total));
    s.push_str(&format!(
        "warranty_expiring_90d,{}\n",
        r.warranty_expiring_90d
    ));
    s.push_str(&format!("contracts_active,{}\n", r.contracts_active));
    s.push_str(&format!(
        "contracts_renewing_90d,{}\n",
        r.contracts_renewing_90d
    ));
    s.push_str("\nasset_type,count\n");
    for b in &r.assets_by_type {
        s.push_str(&format!("{},{}\n", b.label, b.count));
    }
    s.push_str("\nasset_status,count\n");
    for b in &r.assets_by_status {
        s.push_str(&format!("{},{}\n", b.label, b.count));
    }
    s
}
