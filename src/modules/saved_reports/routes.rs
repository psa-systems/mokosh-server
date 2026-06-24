//! PMS-457: HTTP routes for saved reports.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use super::models::{CreateSavedReportRequest, SavedReportResponse, UpdateSavedReportRequest};
use super::service::{ExecuteReportResponse, ReportScope, SavedReportsService};
use crate::modules::auth::RequireAuth;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct SavedReportsRouterState {
    pub service: Arc<SavedReportsService>,
}

pub fn saved_reports_routes(service: SavedReportsService) -> Router {
    let state = SavedReportsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/reports/saved", get(list).post(create))
        .route(
            "/reports/saved/{id}",
            get(get_one).patch(update).delete(delete_one),
        )
        // PMS-477: execute a saved report. POST (not GET) because
        // execution is not cacheable and the SPA will eventually
        // POST overrides on the URL-shape blob; ?page=&per_page=
        // overrides stay on the query string for sharable pagination
        // links.
        .route("/reports/saved/{id}/execute", axum::routing::post(execute))
        .with_state(state)
}

#[derive(Debug, Deserialize, Default)]
struct ExecuteQuery {
    #[serde(default = "default_page")]
    page: u32,
    #[serde(default = "default_per_page")]
    per_page: u32,
}

fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    100
}

#[derive(Debug, Deserialize, Default)]
struct ListQuery {
    /// `mine` | `shared` | `any` (default `any`). Anything else
    /// 400s so the SPA does not silently widen its view.
    #[serde(default)]
    scope: Option<String>,
    /// Optional entity discriminator (`tickets`, `time_entries`,
    /// `invoices`, ...). When set, only reports targeting that
    /// entity are returned.
    #[serde(default)]
    entity_type: Option<String>,
}

async fn list(
    State(s): State<SavedReportsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<SavedReportResponse>>> {
    let scope = match q.scope.as_deref() {
        Some("mine") => ReportScope::Mine,
        Some("shared") => ReportScope::Shared,
        Some("any") | None => ReportScope::Any,
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "Unknown scope='{other}'; expected mine | shared | any",
            )))
        }
    };
    let rows = s
        .service
        .list(u.tenant_id, u.id, scope, q.entity_type.as_deref())
        .await?;
    Ok(Json(rows))
}

async fn get_one(
    State(s): State<SavedReportsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<SavedReportResponse>> {
    let row = s.service.get(u.tenant_id, u.id, id).await?;
    Ok(Json(row))
}

async fn create(
    State(s): State<SavedReportsRouterState>,
    RequireAuth(u): RequireAuth,
    Json(req): Json<CreateSavedReportRequest>,
) -> AppResult<Json<SavedReportResponse>> {
    req.validate().map_err(AppError::from)?;
    let row = s.service.create(u.tenant_id, u.id, req).await?;
    Ok(Json(row))
}

async fn update(
    State(s): State<SavedReportsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateSavedReportRequest>,
) -> AppResult<Json<SavedReportResponse>> {
    req.validate().map_err(AppError::from)?;
    let row = s.service.update(u.tenant_id, u.id, id, req).await?;
    Ok(Json(row))
}

async fn delete_one(
    State(s): State<SavedReportsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    s.service.delete(u.tenant_id, u.id, id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// PMS-477: execute the saved report and return the materialised
/// rows. The service's `get` step enforces the per-user visibility
/// rule (author OR shared), so a caller cannot execute a private
/// report they did not author. Compiler errors (unsupported entity,
/// unknown column, malformed filter value) surface as 400 naming
/// the offender.
async fn execute(
    State(s): State<SavedReportsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Query(q): Query<ExecuteQuery>,
) -> AppResult<Json<ExecuteReportResponse>> {
    let resp = s
        .service
        .execute(u.tenant_id, u.id, id, q.page, q.per_page)
        .await?;
    Ok(Json(resp))
}
