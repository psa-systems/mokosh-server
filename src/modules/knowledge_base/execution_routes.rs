//! Routes for KB article executions on tickets.
//!
//! Two trees share one service: the per-ticket list and create under
//! `/tickets/{ticket_id}/kb-executions`, and the per-execution reads +
//! step toggles under `/kb-executions/{id}/*`. Staff-only in Phase 2a
//! (`RequireAuth`): a contact-plane read is a separate follow-up. The
//! service scopes every query on `tenant_id` from the caller's user,
//! so RLS + the explicit WHERE clauses backstop a dropped filter.

use std::sync::Arc;

use crate::utils::json::Json;
use axum::{
    extract::{Path, State},
    routing::{get, patch},
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::execution_service::KbExecutionService;
use super::models::{
    CheckKbExecutionStepRequest, CreateKbExecutionRequest, KbExecutionResponse,
    KbExecutionStepResponse, KbExecutionSummary,
};
use crate::modules::auth::{RequireAuth, TenantScoped};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct KbExecutionRouterState {
    pub service: Arc<KbExecutionService>,
}

/// Build the KB-execution router.
///
/// Mounted at the top level of the `/api/v1` tree so both the per-ticket
/// subtree (`/tickets/{ticket_id}/kb-executions`) and the per-execution
/// subtree (`/kb-executions/{id}/*`) sit under one state. The ticket
/// router is not involved: the service only needs the ticket id to scope
/// a read, which the path carries.
pub fn kb_execution_routes(service: KbExecutionService) -> Router {
    let state = KbExecutionRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route(
            "/tickets/{ticket_id}/kb-executions",
            get(list_for_ticket).post(create_for_ticket),
        )
        .route("/kb-executions/{id}", get(get_execution))
        .route("/kb-executions/{id}/steps/{index}", patch(set_step_checked))
        .with_state(state)
}

async fn list_for_ticket(
    State(state): State<KbExecutionRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<Vec<KbExecutionSummary>>> {
    Ok(Json(
        state
            .service
            .list_for_ticket(user.tenant(), ticket_id)
            .await?,
    ))
}

async fn create_for_ticket(
    State(state): State<KbExecutionRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
    Json(req): Json<CreateKbExecutionRequest>,
) -> AppResult<Json<KbExecutionResponse>> {
    req.validate()?;
    Ok(Json(
        state
            .service
            .create_execution(
                user.tenant(),
                ticket_id,
                req.article_id,
                user.id,
                &req.values,
            )
            .await?,
    ))
}

async fn get_execution(
    State(state): State<KbExecutionRouterState>,
    RequireAuth(user): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<KbExecutionResponse>> {
    Ok(Json(state.service.get_execution(user.tenant(), id).await?))
}

async fn set_step_checked(
    State(state): State<KbExecutionRouterState>,
    RequireAuth(user): RequireAuth,
    Path((id, index)): Path<(Uuid, i32)>,
    Json(req): Json<CheckKbExecutionStepRequest>,
) -> AppResult<Json<KbExecutionStepResponse>> {
    req.validate()?;
    Ok(Json(
        state
            .service
            .set_step_checked(user.tenant(), id, index, user.id, req.checked)
            .await?,
    ))
}
