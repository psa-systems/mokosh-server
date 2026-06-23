//! PMS-453: HTTP routes for saved dashboards.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::{
    CreateSavedDashboardRequest, SavedDashboardResponse, UpdateSavedDashboardRequest,
};
use super::service::DashboardsService;
use crate::modules::auth::RequireAuth;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct DashboardsRouterState {
    pub service: Arc<DashboardsService>,
}

pub fn dashboard_routes(service: DashboardsService) -> Router {
    let state = DashboardsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/dashboards", get(list).post(create))
        // `/dashboards/default` is hit on every app boot to land the
        // user on their pinned layout; declare it BEFORE `/:id` so the
        // string `default` is not parsed as a UUID path segment and
        // 404'd.
        .route("/dashboards/default", get(get_default))
        .route(
            "/dashboards/:id",
            get(get_one).patch(update).delete(delete_one),
        )
        .with_state(state)
}

async fn list(
    State(s): State<DashboardsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<SavedDashboardResponse>>> {
    let rows = s.service.list_mine(u.tenant_id, u.id).await?;
    Ok(Json(rows))
}

async fn get_default(
    State(s): State<DashboardsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Option<SavedDashboardResponse>>> {
    let row = s.service.get_default(u.tenant_id, u.id).await?;
    Ok(Json(row))
}

async fn get_one(
    State(s): State<DashboardsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<SavedDashboardResponse>> {
    let row = s.service.get(u.tenant_id, u.id, id).await?;
    Ok(Json(row))
}

async fn create(
    State(s): State<DashboardsRouterState>,
    RequireAuth(u): RequireAuth,
    Json(req): Json<CreateSavedDashboardRequest>,
) -> AppResult<Json<SavedDashboardResponse>> {
    req.validate().map_err(AppError::from)?;
    let row = s.service.create(u.tenant_id, u.id, req).await?;
    Ok(Json(row))
}

async fn update(
    State(s): State<DashboardsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateSavedDashboardRequest>,
) -> AppResult<Json<SavedDashboardResponse>> {
    req.validate().map_err(AppError::from)?;
    let row = s.service.update(u.tenant_id, u.id, id, req).await?;
    Ok(Json(row))
}

async fn delete_one(
    State(s): State<DashboardsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    s.service.delete(u.tenant_id, u.id, id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}
