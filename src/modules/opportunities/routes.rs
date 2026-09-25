//! HTTP surface for opportunities.
//!
//! parity record 2026-09-25: `/crm/opportunities`, `/crm/opportunities/{id}`
//! and `/crm/opportunities/{id}/close` have no SPA caller today. PMS-799
//! ships the server plane first (schema, service, routes, integration
//! tests) so the SPA CRM screen can build against a stable surface; the
//! matching mokosh-apps screen is filed as MAPPS-799 and lands after this
//! merges. The route shape is unlikely to move: create, read, list, close
//! are the four verbs the PMS-799 spec commits to.

use crate::utils::json::Json;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    service::OpportunityFilter, CloseOpportunityRequest, CreateOpportunityRequest,
    OpportunitiesService, Opportunity, UpdateOpportunityRequest,
};
use crate::modules::auth::{RequireAuth, TenantScoped};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct OpportunitiesRouterState {
    pub service: Arc<OpportunitiesService>,
}

pub fn opportunities_routes(service: OpportunitiesService) -> Router {
    let state = OpportunitiesRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route(
            "/crm/opportunities",
            get(list_opportunities).post(create_opportunity),
        )
        .route(
            "/crm/opportunities/{id}",
            get(get_opportunity)
                .put(update_opportunity)
                .delete(soft_delete_opportunity),
        )
        .route("/crm/opportunities/{id}/close", post(close_opportunity))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct ListOpportunitiesQuery {
    #[serde(default)]
    company_id: Option<Uuid>,
    #[serde(default)]
    stage: Option<String>,
    /// `true` returns only closed opportunities, `false` only open,
    /// omitted returns both.
    #[serde(default)]
    closed: Option<bool>,
}

async fn list_opportunities(
    State(state): State<OpportunitiesRouterState>,
    RequireAuth(user): RequireAuth,
    Query(query): Query<ListOpportunitiesQuery>,
) -> AppResult<Json<Vec<Opportunity>>> {
    let filter = OpportunityFilter {
        company_id: query.company_id,
        stage: query.stage,
        closed: query.closed,
    };
    Ok(Json(state.service.list(user.tenant(), &filter).await?))
}

async fn create_opportunity(
    State(state): State<OpportunitiesRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<CreateOpportunityRequest>,
) -> AppResult<(StatusCode, Json<Opportunity>)> {
    request.validate()?;
    let created = state
        .service
        .create(user.tenant(), user.id, &request)
        .await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_opportunity(
    State(state): State<OpportunitiesRouterState>,
    RequireAuth(user): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Opportunity>> {
    Ok(Json(state.service.get(user.tenant(), id).await?))
}

async fn update_opportunity(
    State(state): State<OpportunitiesRouterState>,
    RequireAuth(user): RequireAuth,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateOpportunityRequest>,
) -> AppResult<Json<Opportunity>> {
    request.validate()?;
    Ok(Json(
        state.service.update(user.tenant(), id, &request).await?,
    ))
}

async fn close_opportunity(
    State(state): State<OpportunitiesRouterState>,
    RequireAuth(user): RequireAuth,
    Path(id): Path<Uuid>,
    Json(request): Json<CloseOpportunityRequest>,
) -> AppResult<Json<Opportunity>> {
    request.validate()?;
    Ok(Json(
        state.service.close(user.tenant(), id, &request).await?,
    ))
}

async fn soft_delete_opportunity(
    State(state): State<OpportunitiesRouterState>,
    RequireAuth(user): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state.service.soft_delete(user.tenant(), id).await?;
    Ok(StatusCode::NO_CONTENT)
}
