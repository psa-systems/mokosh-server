//! Invitations HTTP routes (PMS-244). Admin-only, tenant-scoped.

use std::sync::Arc;

use crate::utils::json::Json;
use axum::{
    extract::{Path, Query, State},
    routing::{delete, get},
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::InvitationsService;
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct InvitationsRouterState {
    pub service: Arc<InvitationsService>,
}

// SPEC-5.539: every invitation route is admin-only.
pub fn invitations_routes(service: Arc<InvitationsService>) -> Router {
    let state = InvitationsRouterState { service };
    Router::new()
        .route(
            "/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route("/invitations/{id}", delete(revoke_invitation))
        .with_state(state)
}

// SPEC-5.547: pending invitations only; 422 on sort.
async fn list_invitations(
    State(s): State<InvitationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<InvitationResponse>>> {
    pagination.reject_unsupported_sort()?;
    let (items, total) = s.service.list_pending(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

// SPEC-5.540: email format is validated before the service runs (422).
async fn create_invitation(
    State(s): State<InvitationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<CreateInvitationRequest>,
) -> AppResult<Json<InvitationResponse>> {
    req.validate()?;
    Ok(Json(s.service.create(u.tenant(), u.id, &req, &ctx).await?))
}

// SPEC-5.551: success is 200 with an empty body.
async fn revoke_invitation(
    State(s): State<InvitationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.revoke(u.tenant(), id).await
}
