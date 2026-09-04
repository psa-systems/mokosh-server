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
use crate::pdf;
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

const fn date(name: &'static str) -> ParamSpec {
    ParamSpec {
        name,
        kind: "date",
        required: false,
    }
}

/// Which report a descriptor names. `export_report` matches this
/// exhaustively, so a registry entry with no export decision fails to
/// compile instead of 404ing at run time (PMS-839).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReportKind {
    Dashboard,
    Tickets,
    Time,
    RequestTypes,
    Billing,
    Custom,
    Projects,
    Clients,
}

/// A discoverable report type and its parameter schema (PMS-93 AC1).
#[derive(Serialize)]
struct ReportDescriptor {
    /// Not on the wire: it selects the export arm, not something a client
    /// reads. The JSON stays `key` / `name` / `description` / `parameters`.
    #[serde(skip)]
    kind: ReportKind,
    key: &'static str,
    name: &'static str,
    description: &'static str,
    parameters: &'static [ParamSpec],
}

/// The one list of reports (PMS-839). `GET /reports` serves it verbatim and
/// `GET /reports/{key}/export` resolves its path segment through it, so the
/// registry, the export switch and the 404 all read from the same array.
const REPORTS: &[ReportDescriptor] = &[
    ReportDescriptor {
        kind: ReportKind::Dashboard,
        key: "dashboard",
        name: "Operations Dashboard",
        description:
            "Open tickets by priority, SLA at-risk / breached, and the 30-day ticket trend.",
        parameters: &[],
    },
    ReportDescriptor {
        kind: ReportKind::Tickets,
        key: "tickets",
        name: "Ticket Volume & SLA",
        description:
            "Tickets opened by status, total closed, and opened-by-assignee for a date range.",
        parameters: &[date("from"), date("to")],
    },
    ReportDescriptor {
        kind: ReportKind::Time,
        key: "time",
        name: "Technician Utilization",
        description: "Logged minutes by user and by work type for a date range.",
        parameters: &[date("from"), date("to")],
    },
    ReportDescriptor {
        kind: ReportKind::Billing,
        key: "billing",
        name: "Revenue & A/R Aging",
        description: "Invoiced / paid / outstanding totals and A/R aging buckets. Finance only.",
        parameters: &[ParamSpec {
            name: "company_id",
            kind: "uuid",
            required: false,
        }],
    },
    ReportDescriptor {
        kind: ReportKind::RequestTypes,
        key: "request-types",
        name: "Request Type Durations",
        description:
            "How long each client-request type actually takes, measured from the time tracked against the tickets those requests produced.",
        parameters: &[date("from"), date("to")],
    },
    ReportDescriptor {
        kind: ReportKind::Custom,
        key: "custom",
        name: "Custom Report Builder",
        description:
            "Build a report from a whitelisted catalog of sources, dimensions, and measures. Discover the catalog at GET /reports/custom/schema and run via POST /reports/custom. This is the only report key GET /reports/{key}/export cannot serve: the spec travels in a POST body, which a GET export cannot carry, so ask POST /reports/custom for CSV with \"format\": \"csv\" instead. Every other key in this registry exports.",
        parameters: &[],
    },
    ReportDescriptor {
        kind: ReportKind::Projects,
        key: "projects",
        name: "Project Delivery",
        description:
            "Projects by status, budget vs actual hours / amount, task completion, and overdue projects.",
        parameters: &[],
    },
    ReportDescriptor {
        kind: ReportKind::Clients,
        key: "clients",
        name: "Clients & Assets",
        description:
            "Company counts, asset inventory by type and status, warranties expiring soon, and contract renewals.",
        parameters: &[],
    },
];

pub fn reports_routes(service: ReportsService) -> Router {
    let state = ReportsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/reports", get(list_reports))
        .route("/reports/dashboard", get(dashboard))
        .route("/reports/tickets", get(tickets_report))
        .route("/reports/time", get(time_report))
        // PMS-732: measured duration per client-request type.
        .route("/reports/request-types", get(request_types_report))
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
) -> AppResult<Json<&'static [ReportDescriptor]>> {
    Ok(Json(REPORTS))
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
    Ok(Json(
        s.service
            .tickets(u.tenant(), &u.timezone, q.from, q.to)
            .await?,
    ))
}

async fn time_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    Query(q): Query<DateRange>,
) -> AppResult<Json<TimeReportResponse>> {
    Ok(Json(
        s.service
            .time(u.tenant(), &u.timezone, q.from, q.to)
            .await?,
    ))
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

/// Generic export. `:report` selects which report to serialise; `csv` and
/// `pdf` are the implemented formats (PMS-876). Every other value is a 400 and
/// not a 501: one branch serves them all, so an unsupported `format` is an
/// out-of-range query parameter, not a server-side gap (PMS-854). Adding PDF
/// shrank that rejected set; it did not change the status of what is still in
/// it.
async fn export_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    Path(report): Path<String>,
    Query(q): Query<ExportQ>,
) -> AppResult<Response> {
    let format = ExportFormat::parse(&q.format)?;
    // The registry resolves the path segment, so `GET /reports` and this
    // export serve exactly the same set of keys (PMS-839). Plain `{report}`,
    // not `{report:?}`: Debug quoted the name inside the sentence, so the 404
    // read `report "widgets" not found` (PMS-775).
    let Some(descriptor) = REPORTS.iter().find(|r| r.key == report) else {
        return Err(AppError::NotFound(format!("Report {report}")));
    };
    match descriptor.kind {
        ReportKind::Dashboard => emit(
            format,
            descriptor,
            &s.service
                .dashboard(u.tenant(), q.team_id, &u.timezone)
                .await?,
            csv_for_dashboard,
            pdf_for_dashboard,
        ),
        ReportKind::Tickets => emit(
            format,
            descriptor,
            &s.service.tickets(u.tenant(), &u.timezone, q.from, q.to).await?,
            csv_for_tickets,
            pdf_for_tickets,
        ),
        ReportKind::Time => emit(
            format,
            descriptor,
            &s.service.time(u.tenant(), &u.timezone, q.from, q.to).await?,
            csv_for_time,
            pdf_for_time,
        ),
        ReportKind::RequestTypes => emit(
            format,
            descriptor,
            &s.service
                .request_type_durations(u.tenant(), &u.timezone, q.from, q.to)
                .await?,
            csv_for_request_types,
            pdf_for_request_types,
        ),
        // The one registered key a GET export cannot serve: the spec travels
        // in a POST body. Say so rather than 404ing a report that exists.
        // Unchanged by PMS-876: adding a second format does not give a GET a
        // body to carry the spec in.
        ReportKind::Custom => Err(AppError::BadRequest(
            "The custom report cannot be exported through GET /reports/custom/export: its spec travels in a request body. POST /reports/custom with \"format\": \"csv\" instead.".to_string(),
        )),
        ReportKind::Billing => {
            // The billing export carries the same revenue / A/R figures as
            // GET /reports/billing, so it enforces the same finance gate
            // rather than letting any reports-enabled role read it (PMS-350:
            // closing the export side-door around the financial report gate).
            // The gate is above the format switch, so PDF cannot become a
            // second side-door around it.
            if !u.role.can_manage_billing() {
                return Err(AppError::Forbidden(
                    "You do not have permission to do that".to_string(),
                ));
            }
            emit(
                format,
                descriptor,
                &s.service.billing(u.tenant(), q.company_id).await?,
                csv_for_billing,
                pdf_for_billing,
            )
        }
        ReportKind::Projects => emit(
            format,
            descriptor,
            &s.service.projects(u.tenant()).await?,
            csv_for_projects,
            pdf_for_projects,
        ),
        ReportKind::Clients => {
            // The clients export is Client Profitability (invoiced / paid /
            // outstanding), the same financial data as GET /reports/clients,
            // so it enforces the same finance gate as the billing export above
            // rather than leaving a CSV side-door open (PMS-350). Same reason
            // it sits above the format switch.
            if !u.role.can_manage_billing() {
                return Err(AppError::Forbidden(
                    "You do not have permission to do that".to_string(),
                ));
            }
            emit(
                format,
                descriptor,
                &s.service.clients(u.tenant()).await?,
                csv_for_clients,
                pdf_for_clients,
            )
        }
    }
}

/// Which serialization the caller asked for.
///
/// An enumerated query parameter, so a value outside the implemented set is an
/// out-of-range request and stays a 400 rather than becoming a 501 (PMS-854).
/// Adding PDF shrinks the rejected set; it does not change the status for what
/// remains in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ExportFormat {
    Csv,
    Pdf,
}

impl ExportFormat {
    fn parse(raw: &str) -> AppResult<Self> {
        if raw.eq_ignore_ascii_case("csv") {
            Ok(Self::Csv)
        } else if raw.eq_ignore_ascii_case("pdf") {
            Ok(Self::Pdf)
        } else {
            Err(AppError::BadRequest(format!(
                "Format {raw:?} is not supported; 'csv' and 'pdf' are"
            )))
        }
    }
}

/// Serialize one report's data in the requested format.
///
/// The two writers travel together in one call rather than in two arms of a
/// format switch inside every report arm. That is the point: a report cannot
/// acquire a CSV writer and no PDF one, because there is nowhere to put a
/// half-pair, and `export_report` still matches `ReportKind` exhaustively so a
/// new registry entry fails to compile until both exist (PMS-839).
fn emit<T>(
    format: ExportFormat,
    descriptor: &ReportDescriptor,
    data: &T,
    to_csv: fn(&T) -> String,
    to_pdf: fn(&T, &str) -> pdf::Document,
) -> AppResult<Response> {
    match format {
        ExportFormat::Csv => Ok((
            [(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")],
            to_csv(data),
        )
            .into_response()),
        ExportFormat::Pdf => {
            let bytes = pdf::render(&to_pdf(data, descriptor.name))?;
            Ok((
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "application/pdf".to_string(),
                    ),
                    // The CSV branch deliberately keeps no `Content-Disposition`:
                    // it is an existing response the SPA already consumes, and
                    // changing its headers is not this issue's to do. A PDF is
                    // new, and a browser handed one with no disposition renders
                    // it in place under a URL ending in `/export`.
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}.pdf\"", descriptor.key),
                    ),
                ],
                bytes,
            )
                .into_response())
        }
    }
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

/// PMS-772. `count` is the grouped-count header every other export uses.
/// A request type with no tracked time in the period leaves the three
/// measurement cells empty rather than writing 0: no data is not a zero
/// measurement, which is the distinction the JSON nulls carry (PMS-732).
fn csv_for_request_types(r: &RequestTypeDurationsResponse) -> String {
    let mut s = format!(
        "from,to\n{},{}\n\nrequest_type,slug,kb_article,count,total_minutes,average_minutes\n",
        r.from, r.to
    );
    for t in &r.request_types {
        s.push_str(&format!(
            "{},{},{},{},{},{}\n",
            custom::csv_cell(&t.form_name),
            custom::csv_cell(&t.form_slug),
            custom::csv_cell(t.kb_article_title.as_deref().unwrap_or("")),
            t.ticket_count.map(|c| c.to_string()).unwrap_or_default(),
            t.total_minutes.map(|m| m.to_string()).unwrap_or_default(),
            t.average_minutes
                .map(|m| format!("{m:.1}"))
                .unwrap_or_default(),
        ));
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

// ---------------------------------------------------------------------------
// PDF writers (PMS-876). One per CSV writer above, and paired with it at the
// `emit` call site so neither can exist without the other.
//
// Each builds a `pdf::Document` and lays out nothing: the title is the
// registry's own `name`, so a report renamed in one place is renamed in the
// export too, and the sections mirror the CSV's blocks so the two formats are
// the same report rather than two reports.
// ---------------------------------------------------------------------------

/// A count column formatted the way every table here formats one.
fn buckets(rows: &[Bucket]) -> Vec<Vec<String>> {
    rows.iter()
        .map(|b| vec![b.label.clone(), b.count.to_string()])
        .collect()
}

fn pdf_for_dashboard(r: &DashboardResponse, title: &str) -> pdf::Document {
    pdf::Document::new(title)
        .table(
            "Open tickets by priority",
            vec!["Priority".into(), "Open".into()],
            buckets(&r.open_by_priority),
        )
        .fields(
            "SLA",
            vec![
                ("At risk".into(), r.sla_warnings.to_string()),
                ("Breached".into(), r.sla_breached.to_string()),
            ],
        )
        .table(
            "Tickets opened, last 30 days",
            vec!["Date".into(), "Opened".into()],
            r.ticket_trend_30d
                .iter()
                .map(|d| vec![d.date.to_string(), d.count.to_string()])
                .collect(),
        )
}

fn pdf_for_tickets(r: &TicketsReportResponse, title: &str) -> pdf::Document {
    pdf::Document::new(title)
        .subtitle(format!("{} to {}", r.from, r.to))
        .table(
            "Opened by status",
            vec!["Status".into(), "Opened".into()],
            buckets(&r.opened_by_status),
        )
        .fields(
            "Totals",
            vec![("Closed".into(), r.closed_total.to_string())],
        )
        .table(
            "Opened by assignee",
            vec!["Assignee".into(), "Opened".into()],
            r.opened_by_assignee
                .iter()
                .map(|a| {
                    vec![
                        a.assignee_id
                            .map(|u| u.to_string())
                            .unwrap_or_else(|| "unassigned".into()),
                        a.count.to_string(),
                    ]
                })
                .collect(),
        )
}

fn pdf_for_time(r: &TimeReportResponse, title: &str) -> pdf::Document {
    let by_id = |rows: &[IdCount]| -> Vec<Vec<String>> {
        rows.iter()
            .map(|i| vec![i.id.to_string(), i.count.to_string()])
            .collect()
    };
    pdf::Document::new(title)
        .subtitle(format!("{} to {}", r.from, r.to))
        .table(
            "Minutes by user",
            vec!["User".into(), "Minutes".into()],
            by_id(&r.minutes_by_user),
        )
        .table(
            "Minutes by work type",
            vec!["Work type".into(), "Minutes".into()],
            by_id(&r.minutes_by_work_type),
        )
}

/// A request type with no tracked time in the period leaves its three
/// measurement cells empty rather than writing 0, exactly as the CSV does: no
/// data is not a zero measurement (PMS-732).
fn pdf_for_request_types(r: &RequestTypeDurationsResponse, title: &str) -> pdf::Document {
    pdf::Document::new(title)
        .subtitle(format!("{} to {}", r.from, r.to))
        .table(
            "Measured duration by request type",
            vec![
                "Request type".into(),
                "Slug".into(),
                "KB article".into(),
                "Tickets".into(),
                "Total min".into(),
                "Average min".into(),
            ],
            r.request_types
                .iter()
                .map(|t| {
                    vec![
                        t.form_name.clone(),
                        t.form_slug.clone(),
                        t.kb_article_title.clone().unwrap_or_default(),
                        t.ticket_count.map(|c| c.to_string()).unwrap_or_default(),
                        t.total_minutes.map(|m| m.to_string()).unwrap_or_default(),
                        t.average_minutes
                            .map(|m| format!("{m:.1}"))
                            .unwrap_or_default(),
                    ]
                })
                .collect(),
        )
}

fn pdf_for_billing(r: &BillingReportResponse, title: &str) -> pdf::Document {
    pdf::Document::new(title)
        .fields(
            "Totals",
            vec![
                ("Invoiced".into(), r.invoiced.to_string()),
                ("Paid".into(), r.paid.to_string()),
                ("Outstanding".into(), r.outstanding.to_string()),
            ],
        )
        .table(
            "A/R aging",
            vec!["Bucket".into(), "Total".into()],
            r.aging
                .iter()
                .map(|b| vec![b.bucket.clone(), b.total.to_string()])
                .collect(),
        )
}

fn pdf_for_projects(r: &ProjectsReportResponse, title: &str) -> pdf::Document {
    pdf::Document::new(title)
        .table(
            "Projects by status",
            vec!["Status".into(), "Count".into()],
            buckets(&r.by_status),
        )
        .fields(
            "Budget and actuals",
            vec![
                ("Budget hours".into(), r.budget_hours.to_string()),
                ("Budget amount".into(), r.budget_amount.to_string()),
                ("Actual hours".into(), r.actual_hours.to_string()),
                ("Actual amount".into(), r.actual_amount.to_string()),
                ("Tasks total".into(), r.tasks_total.to_string()),
                ("Tasks completed".into(), r.tasks_completed.to_string()),
                ("Overdue".into(), r.overdue.to_string()),
            ],
        )
}

fn pdf_for_clients(r: &ClientsReportResponse, title: &str) -> pdf::Document {
    pdf::Document::new(title)
        .fields(
            "Totals",
            vec![
                ("Companies".into(), r.companies_total.to_string()),
                ("Companies active".into(), r.companies_active.to_string()),
                ("Assets".into(), r.assets_total.to_string()),
                (
                    "Warranties expiring in 90 days".into(),
                    r.warranty_expiring_90d.to_string(),
                ),
                ("Contracts active".into(), r.contracts_active.to_string()),
                (
                    "Contracts renewing in 90 days".into(),
                    r.contracts_renewing_90d.to_string(),
                ),
            ],
        )
        .table(
            "Assets by type",
            vec!["Type".into(), "Count".into()],
            buckets(&r.assets_by_type),
        )
        .table(
            "Assets by status",
            vec!["Status".into(), "Count".into()],
            buckets(&r.assets_by_status),
        )
}

/// PMS-732: how long each client-request type actually takes, measured from
/// the time tracked against the tickets those requests produced.
async fn request_types_report(
    State(s): State<ReportsRouterState>,
    RequireReports { user: u, .. }: RequireReports,
    Query(q): Query<DateRange>,
) -> AppResult<Json<crate::modules::reports::service::RequestTypeDurationsResponse>> {
    Ok(Json(
        s.service
            .request_type_durations(u.tenant(), &u.timezone, q.from, q.to)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PMS-839: the exhaustive match in `export_report` only gates a new
    /// registry entry if that entry needs a new `ReportKind`. Reusing a
    /// variant would slip an entry past the compiler and silently export
    /// another report's data under it.
    #[test]
    fn every_descriptor_has_its_own_key_and_kind() {
        for (i, r) in REPORTS.iter().enumerate() {
            for other in &REPORTS[i + 1..] {
                assert_ne!(r.key, other.key, "two registry entries share a key");
                assert_ne!(
                    r.kind, other.kind,
                    "{} and {} share a ReportKind, so one of them never reached \
                     the export match as itself",
                    r.key, other.key
                );
            }
        }
    }

    /// The wire shape predates the array and clients read it, so `kind` must
    /// stay off it: the descriptor serialises as key / name / description /
    /// parameters and nothing else.
    #[test]
    fn the_registry_wire_shape_is_unchanged() {
        let json = serde_json::to_value(REPORTS).expect("serialise the registry");
        let entries = json.as_array().expect("the registry is a JSON array");
        assert_eq!(entries.len(), REPORTS.len());
        for entry in entries {
            // serde_json orders an object's keys alphabetically, so compare
            // against the sorted field set rather than declaration order.
            let fields: Vec<&str> = entry
                .as_object()
                .expect("a descriptor is a JSON object")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                fields,
                ["description", "key", "name", "parameters"],
                "descriptor {entry}"
            );
        }
    }
}
