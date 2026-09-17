//! MAPPS-877: `GET /api/v1/members` route.
//!
//! Mount at `/api/v1/members`. Manager-gated read; the SPA's People
//! pane is the primary consumer.

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use std::sync::Arc;

use super::service::{MembersFilter, MembersService};
use crate::modules::auth::middleware::RequireManager;
use crate::utils::error::AppResult;
use crate::utils::pagination::PaginationParams;
use mokosh_types::members::MembersResponse;

#[derive(Clone)]
pub struct MembersRouterState {
    pub members_service: Arc<MembersService>,
}

pub fn members_routes(members_service: MembersService) -> Router {
    let state = MembersRouterState {
        members_service: Arc::new(members_service),
    };
    Router::<MembersRouterState>::new()
        .route("/", get(list_members))
        .with_state(state)
}

async fn list_members(
    State(state): State<MembersRouterState>,
    manager: RequireManager,
    Query(filter): Query<MembersFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<MembersResponse>> {
    let caller = &manager.0;
    // `caller.id` is the caller's bunyip_user_id for their own tenant
    // (migration 221 backfilled `users.bunyip_user_id = users.id`).
    // The sharing outbox fan-out at `owner_grants_routes` uses the
    // same `caller.id` for the same reason.
    let response = state
        .members_service
        .list(caller.tenant_id, caller.id, &filter, &pagination)
        .await?;
    Ok(Json(response))
}
