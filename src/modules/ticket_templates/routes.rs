//! PMS-448 AC4: HTTP routes for ticket templates.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use super::models::{
    CreateTicketTemplateRequest, TicketTemplateResponse, UpdateTicketTemplateRequest,
};
use super::service::TicketTemplatesService;
use crate::modules::auth::RequireAdminUser;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
struct TicketTemplatesRouterState {
    service: Arc<TicketTemplatesService>,
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    /// When `true`, narrows the list to the new-ticket picker's view
    /// (active templates only). Defaults to false so the admin
    /// management screen sees retired templates too.
    #[serde(default)]
    active_only: bool,
}

pub fn ticket_template_routes(service: TicketTemplatesService) -> Router {
    let state = TicketTemplatesRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/ticket-templates", get(list).post(create))
        .route(
            "/ticket-templates/{id}",
            get(get_one).patch(update).delete(delete_one),
        )
        .with_state(state)
}

// Authoring + reading ticket templates is admin-gated to match the
// workflow-rule surface: both are tenant-wide automation config an
// admin owns, not per-agent data.

async fn list(
    State(s): State<TicketTemplatesRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<TicketTemplateResponse>>> {
    Ok(Json(s.service.list(u.tenant_id, q.active_only).await?))
}

async fn get_one(
    State(s): State<TicketTemplatesRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<TicketTemplateResponse>> {
    Ok(Json(s.service.get(u.tenant_id, id).await?))
}

async fn create(
    State(s): State<TicketTemplatesRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Json(req): Json<CreateTicketTemplateRequest>,
) -> AppResult<Json<TicketTemplateResponse>> {
    req.validate().map_err(AppError::from)?;
    Ok(Json(s.service.create(u.tenant_id, u.id, req).await?))
}

async fn update(
    State(s): State<TicketTemplatesRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTicketTemplateRequest>,
) -> AppResult<Json<TicketTemplateResponse>> {
    req.validate().map_err(AppError::from)?;
    Ok(Json(s.service.update(u.tenant_id, id, req).await?))
}

async fn delete_one(
    State(s): State<TicketTemplatesRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    s.service.delete(u.tenant_id, id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}
