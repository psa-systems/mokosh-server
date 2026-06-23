//! PMS-448: HTTP routes for workflow rules.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::{
    CreateWorkflowRuleRequest, UpdateWorkflowRuleRequest, WorkflowRuleResponse,
    WorkflowRuleRunResponse,
};
use super::service::WorkflowsService;
use crate::modules::auth::{RequireAdmin, RequireAuth};
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct WorkflowsRouterState {
    pub service: Arc<WorkflowsService>,
}

pub fn workflow_routes(service: WorkflowsService) -> Router {
    let state = WorkflowsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/workflow-rules", get(list).post(create))
        .route(
            "/workflow-rules/{id}",
            get(get_one).patch(update).delete(delete_one),
        )
        // Per-ticket rule-run timeline. Used by the ticket detail
        // page to answer "what auto-routed this ticket?".
        .route("/tickets/{id}/workflow-runs", get(list_ticket_runs))
        .with_state(state)
}

// RequireAdmin: workflow rules can reassign tickets and add
// internal notes, so the create / mutate surfaces are admin-only.
// Listing + reading is also admin-only to keep the rule definitions
// (which can encode business logic the rest of the org should not
// see) inside the admin tier.

async fn list(
    State(s): State<WorkflowsRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
) -> AppResult<Json<Vec<WorkflowRuleResponse>>> {
    Ok(Json(s.service.list(u.tenant_id).await?))
}

async fn get_one(
    State(s): State<WorkflowsRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<Json<WorkflowRuleResponse>> {
    Ok(Json(s.service.get(u.tenant_id, id).await?))
}

async fn create(
    State(s): State<WorkflowsRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
    Json(req): Json<CreateWorkflowRuleRequest>,
) -> AppResult<Json<WorkflowRuleResponse>> {
    req.validate().map_err(AppError::from)?;
    Ok(Json(s.service.create(u.tenant_id, u.id, req).await?))
}

async fn update(
    State(s): State<WorkflowsRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateWorkflowRuleRequest>,
) -> AppResult<Json<WorkflowRuleResponse>> {
    req.validate().map_err(AppError::from)?;
    Ok(Json(s.service.update(u.tenant_id, id, req).await?))
}

async fn delete_one(
    State(s): State<WorkflowsRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    s.service.delete(u.tenant_id, id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// `GET /api/v1/tickets/{id}/workflow-runs` - "what fired on this
/// ticket". Admin-only because the rule definitions are admin-tier;
/// surfacing which rule fired indirectly reveals them.
async fn list_ticket_runs(
    State(s): State<WorkflowsRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<WorkflowRuleRunResponse>>> {
    Ok(Json(
        s.service
            .list_runs_for_entity(u.tenant_id, "tickets", id)
            .await?,
    ))
}
