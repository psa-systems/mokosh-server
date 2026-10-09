//! `GET /api/v1/members` surface.
//!
//! Gated on `RequireManager` so the read matches `list_users`' auth posture
//! (MAPPS-877 phase 1); the merged list exposes everything an admin or
//! manager already sees across two separate endpoints, so a role that
//! could not read either should not reach the unified reader either.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use validator::Validate;

use crate::modules::auth::{RequireManager, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::pagination::PaginationParams;

use mokosh_types::members::MembersResponse;

use super::service::{MembersFilter, MembersService};

#[derive(Clone)]
pub struct MembersRouterState {
    pub members_service: Arc<MembersService>,
}

pub fn members_routes(members_service: Arc<MembersService>) -> Router {
    let state = MembersRouterState { members_service };
    Router::new()
        .route("/members", get(list_members))
        .with_state(state)
}

async fn list_members(
    State(state): State<MembersRouterState>,
    manager: RequireManager,
    Query(filter): Query<MembersFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<MembersResponse>> {
    filter.validate()?;
    filter.validate_enums()?;
    // PMS-1194: the service sorts the merged set in Rust after the fan-out
    // (there is no single ORDER BY to delegate `?sort=` to), so an
    // unsupported `sort` query parameter is refused here rather than
    // silently ignored.
    pagination.reject_unsupported_sort()?;
    let caller = manager.0;
    let response = state
        .members_service
        .list(caller.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(response))
}
