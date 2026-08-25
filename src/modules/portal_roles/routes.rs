//! HTTP surface for the portal-role CRUD (prompt 007).
//!
//! Mounted at `/api/v1/portal-roles` by `create_api_router`, so the
//! paths inside are relative to that prefix. `/capabilities` is
//! registered BEFORE `/{id}` so the literal segment wins the path
//! match; a bare `/{id}` would swallow it as a Uuid deserialisation
//! attempt and 400.

use axum::{
    extract::{Path, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::AppResult;

use super::models::*;
use super::service::PortalRoleService;

#[derive(Clone)]
pub struct PortalRoleRouterState {
    pub service: Arc<PortalRoleService>,
}

pub fn portal_role_routes(service: PortalRoleService) -> Router {
    let state = PortalRoleRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/", get(list_roles))
        .route("/", post(create_role))
        .route("/capabilities", get(list_capabilities))
        .route("/{id}", get(get_role))
        .route("/{id}", put(update_role))
        .route("/{id}", delete(delete_role))
        .with_state(state)
}

async fn list_roles(
    State(state): State<PortalRoleRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<PortalRoleSummary>>> {
    let roles = state.service.list_roles(user.tenant()).await?;
    Ok(Json(roles))
}

async fn list_capabilities(
    State(state): State<PortalRoleRouterState>,
    _admin: RequireAdmin,
    RequireAuth(_user): RequireAuth,
) -> AppResult<Json<ListCapabilitiesResponse>> {
    Ok(Json(state.service.capability_labels()))
}

async fn get_role(
    State(state): State<PortalRoleRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<PortalRole>> {
    Ok(Json(state.service.get_role(user.tenant(), id).await?))
}

async fn create_role(
    State(state): State<PortalRoleRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreatePortalRoleRequest>,
) -> AppResult<Json<PortalRole>> {
    request.validate()?;
    let role = state
        .service
        .create_role(user.tenant(), request.name, request.capabilities, &ctx)
        .await?;
    Ok(Json(role))
}

async fn update_role(
    State(state): State<PortalRoleRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdatePortalRoleRequest>,
) -> AppResult<Json<PortalRole>> {
    request.validate()?;
    let role = state
        .service
        .update_role(user.tenant(), id, request.name, request.capabilities, &ctx)
        .await?;
    Ok(Json(role))
}

async fn delete_role(
    State(state): State<PortalRoleRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    state.service.delete_role(user.tenant(), id, &ctx).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
