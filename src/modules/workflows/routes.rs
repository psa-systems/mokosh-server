//! PMS-448: HTTP routes for workflow rules.
//!
//! parity record 2026-09-22: workflow-rule CRUD and per-ticket run history
//! serve a Settings > Automation admin surface with no SPA yet. Deferred,
//! not dead: the rule engine drives ticket automation and the routes let an
//! admin edit its config out-of-band. Remove this note when the SPA lands.
//!
//! Exempted paths (named per MAPPS-1083):
//!   - `/workflow-rules`
//!   - `/workflow-rules/{id}`

use std::sync::Arc;

use crate::utils::json::Json;
use axum::{
    extract::{Path, State},
    routing::get,
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::{
    CreateWorkflowRuleRequest, UpdateWorkflowRuleRequest, WorkflowRuleResponse,
    WorkflowRuleRunResponse,
};
use super::service::WorkflowsService;
use crate::modules::auth::RequireAdminUser;
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

// SPEC-7.155: GET /api/v1/workflow-rules requires an admin user and lists every
// rule for the caller's tenant, ordered priority ASC, created_at ASC.
async fn list(
    State(s): State<WorkflowsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
) -> AppResult<Json<Vec<WorkflowRuleResponse>>> {
    Ok(Json(s.service.list(u.tenant_id).await?))
}

// SPEC-7.156: GET /api/v1/workflow-rules/{id} requires an admin user and scopes
// the lookup to the caller's tenant; a missing row surfaces as 404 "Workflow rule".
async fn get_one(
    State(s): State<WorkflowsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<WorkflowRuleResponse>> {
    Ok(Json(s.service.get(u.tenant_id, id).await?))
}

// SPEC-7.157: POST /api/v1/workflow-rules requires an admin, validates the DTO, then binds
// the new row to the caller's tenant_id and created_by_id.
async fn create(
    State(s): State<WorkflowsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Json(req): Json<CreateWorkflowRuleRequest>,
) -> AppResult<Json<WorkflowRuleResponse>> {
    req.validate().map_err(AppError::from)?;
    Ok(Json(s.service.create(u.tenant_id, u.id, req).await?))
}

// SPEC-7.151,7.158: PATCH /api/v1/workflow-rules/{id} requires an admin, validates
// (name length 1..=200 when Some), then applies only the non-null request fields.
async fn update(
    State(s): State<WorkflowsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateWorkflowRuleRequest>,
) -> AppResult<Json<WorkflowRuleResponse>> {
    req.validate().map_err(AppError::from)?;
    Ok(Json(s.service.update(u.tenant_id, id, req).await?))
}

// SPEC-7.160: DELETE /api/v1/workflow-rules/{id} requires an admin user; on
// success it returns {"deleted": true}.
async fn delete_one(
    State(s): State<WorkflowsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    s.service.delete(u.tenant_id, id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// `GET /api/v1/tickets/{id}/workflow-runs` - "what fired on this
/// ticket". Admin-only because the rule definitions are admin-tier;
/// surfacing which rule fired indirectly reveals them.
// SPEC-7.161: requires an admin user and returns every workflow_rule_runs row
// for this ticket, scoped to the caller's tenant, ordered ran_at DESC.
async fn list_ticket_runs(
    State(s): State<WorkflowsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<WorkflowRuleRunResponse>>> {
    Ok(Json(
        s.service
            .list_runs_for_entity(u.tenant_id, "tickets", id)
            .await?,
    ))
}
