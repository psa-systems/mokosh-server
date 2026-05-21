//! Reports HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::NaiveDate;
use serde::Deserialize;
use uuid::Uuid;

use super::service::*;
use crate::modules::auth::{RequireAuth, RequireManager};
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct ReportsRouterState {
    pub service: Arc<ReportsService>,
}

pub fn reports_routes(service: ReportsService) -> Router {
    let state = ReportsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/reports/dashboard", get(dashboard))
        .route("/reports/tickets", get(tickets_report))
        .route("/reports/time", get(time_report))
        .route("/reports/billing", get(billing_report))
        .route("/reports/{report}/export", get(export_report))
        .with_state(state)
}

#[derive(Deserialize)]
struct DateRange {
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
}

async fn dashboard(
    State(s): State<ReportsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<DashboardResponse>> {
    Ok(Json(s.service.dashboard(u.tenant_id).await?))
}

async fn tickets_report(
    State(s): State<ReportsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(q): Query<DateRange>,
) -> AppResult<Json<TicketsReportResponse>> {
    Ok(Json(s.service.tickets(u.tenant_id, q.from, q.to).await?))
}

async fn time_report(
    State(s): State<ReportsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(q): Query<DateRange>,
) -> AppResult<Json<TimeReportResponse>> {
    Ok(Json(s.service.time(u.tenant_id, q.from, q.to).await?))
}

#[derive(Deserialize)]
struct BillingQ {
    company_id: Option<Uuid>,
}

async fn billing_report(
    State(s): State<ReportsRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Query(q): Query<BillingQ>,
) -> AppResult<Json<BillingReportResponse>> {
    Ok(Json(s.service.billing(u.tenant_id, q.company_id).await?))
}

#[derive(Deserialize)]
struct ExportQ {
    #[serde(default = "default_csv")]
    format: String,
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
    company_id: Option<Uuid>,
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
    RequireAuth(u): RequireAuth,
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
        "dashboard" => csv_for_dashboard(&s.service.dashboard(u.tenant_id).await?),
        "tickets" => csv_for_tickets(&s.service.tickets(u.tenant_id, q.from, q.to).await?),
        "time" => csv_for_time(&s.service.time(u.tenant_id, q.from, q.to).await?),
        "billing" => csv_for_billing(&s.service.billing(u.tenant_id, q.company_id).await?),
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
