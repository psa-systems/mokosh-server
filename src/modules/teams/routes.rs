//! Team API routes (PMS-791 / MAPPS-461).
//!
//! All write endpoints gate on `RequireAdmin` (per open-questions Q1 + Q2
//! default = A). Read endpoints gate on `RequireAuth`. `RequireAdmin` is
//! `[super_admin, admin]`; anything else 403s.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    AddTeamMemberRequest, CreateTeamRequest, Team, TeamListFilters, TeamMember, TeamMemberWithUser,
    TeamWithMembers, TeamsService, UpdateTeamMemberRoleRequest, UpdateTeamRequest,
};
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct TeamsRouterState {
    pub teams_service: Arc<TeamsService>,
}

pub fn teams_routes(teams_service: TeamsService) -> Router {
    let state = TeamsRouterState {
        teams_service: Arc::new(teams_service),
    };
    Router::new()
        .route("/", get(list_teams).post(create_team))
        .route(
            "/{team_id}",
            get(get_team).put(update_team).delete(soft_delete_team),
        )
        .route("/{team_id}/members", get(list_members).post(add_member))
        .route(
            "/{team_id}/members/{user_id}",
            put(update_member_role).delete(remove_member),
        )
        .with_state(state)
}

/// Companion `/me/teams` router: the caller's own team memberships.
/// Separate from `teams_routes` so it can mount under `/me` cleanly.
pub fn me_teams_routes(teams_service: TeamsService) -> Router {
    let state = TeamsRouterState {
        teams_service: Arc::new(teams_service),
    };
    Router::new()
        .route("/teams", get(list_my_teams))
        .with_state(state)
}

// ----------------------------------------------------------------------
// Query params
// ----------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ListTeamsQuery {
    /// `true` (default) = active only, `false` = archived only,
    /// `all` = both. Any other value defaults to active.
    #[serde(default)]
    pub active: Option<String>,
    #[serde(default)]
    pub manager_id: Option<Uuid>,
}

impl ListTeamsQuery {
    fn to_filters(&self) -> TeamListFilters {
        let active_raw = self
            .active
            .as_deref()
            .unwrap_or("true")
            .to_ascii_lowercase();
        let (include_inactive, only_inactive) = match active_raw.as_str() {
            "all" => (true, false),
            "false" | "0" | "no" => (false, true),
            _ => (false, false),
        };
        TeamListFilters {
            include_inactive,
            only_inactive,
            manager_id: self.manager_id,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct GetTeamQuery {
    #[serde(default)]
    pub include: Option<String>,
}

// ----------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------

/// `GET /api/v1/teams` — list teams in the caller's tenant.
async fn list_teams(
    State(state): State<TeamsRouterState>,
    RequireAuth(user): RequireAuth,
    Query(query): Query<ListTeamsQuery>,
) -> AppResult<Json<Vec<Team>>> {
    let teams = state
        .teams_service
        .list_teams(user.tenant(), query.to_filters())
        .await?;
    Ok(Json(teams))
}

/// `POST /api/v1/teams` — RequireAdmin. Creates one team.
async fn create_team(
    State(state): State<TeamsRouterState>,
    admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateTeamRequest>,
) -> AppResult<(StatusCode, Json<Team>)> {
    request.validate()?;
    let team = state
        .teams_service
        .create_team(admin.0.tenant(), &request, &ctx)
        .await?;
    Ok((StatusCode::CREATED, Json(team)))
}

/// `GET /api/v1/teams/{team_id}` — one team, optionally with member roster
/// via `?include=members`.
async fn get_team(
    State(state): State<TeamsRouterState>,
    RequireAuth(user): RequireAuth,
    Path(team_id): Path<Uuid>,
    Query(query): Query<GetTeamQuery>,
) -> AppResult<impl IntoResponse> {
    let include_members = query
        .include
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("members"));
    if include_members {
        let bundle: TeamWithMembers = state
            .teams_service
            .get_team_with_members(user.tenant(), team_id)
            .await?;
        Ok(Json(serde_json::to_value(bundle).unwrap()).into_response())
    } else {
        let team = state.teams_service.get_team(user.tenant(), team_id).await?;
        Ok(Json(serde_json::to_value(team).unwrap()).into_response())
    }
}

/// `PUT /api/v1/teams/{team_id}` — RequireAdmin. Partial update.
async fn update_team(
    State(state): State<TeamsRouterState>,
    admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path(team_id): Path<Uuid>,
    Json(request): Json<UpdateTeamRequest>,
) -> AppResult<Json<Team>> {
    request.validate()?;
    let team = state
        .teams_service
        .update_team(admin.0.tenant(), team_id, &request, &ctx)
        .await?;
    Ok(Json(team))
}

/// `DELETE /api/v1/teams/{team_id}` — RequireAdmin. Soft delete only.
async fn soft_delete_team(
    State(state): State<TeamsRouterState>,
    admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path(team_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state
        .teams_service
        .soft_delete_team(admin.0.tenant(), team_id, &ctx)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/teams/{team_id}/members` — member roster with user joins.
async fn list_members(
    State(state): State<TeamsRouterState>,
    RequireAuth(user): RequireAuth,
    Path(team_id): Path<Uuid>,
) -> AppResult<Json<Vec<TeamMemberWithUser>>> {
    let members = state
        .teams_service
        .list_members(user.tenant(), team_id)
        .await?;
    Ok(Json(members))
}

/// `POST /api/v1/teams/{team_id}/members` — RequireAdmin. Add a member.
async fn add_member(
    State(state): State<TeamsRouterState>,
    admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path(team_id): Path<Uuid>,
    Json(request): Json<AddTeamMemberRequest>,
) -> AppResult<(StatusCode, Json<TeamMember>)> {
    request.validate()?;
    let member = state
        .teams_service
        .add_member(admin.0.tenant(), team_id, &request, &ctx)
        .await?;
    Ok((StatusCode::CREATED, Json(member)))
}

/// `PUT /api/v1/teams/{team_id}/members/{user_id}` — RequireAdmin.
async fn update_member_role(
    State(state): State<TeamsRouterState>,
    admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path((team_id, user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateTeamMemberRoleRequest>,
) -> AppResult<Json<TeamMember>> {
    request.validate()?;
    let member = state
        .teams_service
        .update_member_role(admin.0.tenant(), team_id, user_id, &request, &ctx)
        .await?;
    Ok(Json(member))
}

/// `DELETE /api/v1/teams/{team_id}/members/{user_id}` — RequireAdmin.
/// Idempotent: a repeat delete returns 204, not 404.
async fn remove_member(
    State(state): State<TeamsRouterState>,
    admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path((team_id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    state
        .teams_service
        .remove_member(admin.0.tenant(), team_id, user_id, &ctx)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/me/teams` — teams the caller belongs to.
async fn list_my_teams(
    State(state): State<TeamsRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<Team>>> {
    let teams = state
        .teams_service
        .list_teams_for_user(user.tenant(), user.id)
        .await?;
    Ok(Json(teams))
}
