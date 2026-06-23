//! PMS-451: HTTP routes for ticket approvals.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::{ApprovalResponse, CreateApprovalRequest, DecideApprovalRequest};
use super::service::ApprovalsService;
use crate::modules::auth::RequireAuth;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct ApprovalsRouterState {
    pub service: Arc<ApprovalsService>,
}

pub fn approval_routes(service: ApprovalsService) -> Router {
    let state = ApprovalsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // Per-ticket list + create. Mounted under `/tickets/{ticket_id}`
        // so the SPA's ticket detail page hits one prefix for both
        // the timeline read and the "Request approval" submit. Axum
        // 0.8 dropped the leading-colon capture syntax in favour of
        // braces; using `:ticket_id` here panics at router build.
        .route(
            "/tickets/{ticket_id}/approvals",
            get(list_for_ticket).post(create_for_ticket),
        )
        // Caller's pending decision queue. Used by the SPA's top bar
        // badge + the dedicated "My approvals" page.
        .route("/approvals/pending", get(pending_for_caller))
        // Decision + cancel paths. Cancel is DELETE because the row
        // remains in the DB with status='cancelled'; this matches the
        // soft-delete posture across the rest of the API.
        .route("/approvals/{id}/decision", post(decide))
        .route("/approvals/{id}", delete(cancel))
        .with_state(state)
}

async fn list_for_ticket(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<Vec<ApprovalResponse>>> {
    let rows = s.service.list_for_ticket(u.tenant_id, ticket_id).await?;
    Ok(Json(rows))
}

async fn create_for_ticket(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(ticket_id): Path<Uuid>,
    Json(req): Json<CreateApprovalRequest>,
) -> AppResult<Json<ApprovalResponse>> {
    req.validate().map_err(AppError::from)?;
    let row = s.service.create(u.tenant_id, ticket_id, u.id, req).await?;
    Ok(Json(row))
}

async fn pending_for_caller(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<ApprovalResponse>>> {
    // CurrentUser carries a single role; pass it as a one-element list
    // so the service stays role-source-agnostic and a future
    // multi-role identity can pass the full set without a signature
    // change.
    let roles = vec![u.role.as_str().to_string()];
    let rows = s
        .service
        .pending_for_user(u.tenant_id, u.id, &roles)
        .await?;
    Ok(Json(rows))
}

async fn decide(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<DecideApprovalRequest>,
) -> AppResult<Json<ApprovalResponse>> {
    req.validate().map_err(AppError::from)?;
    let row = s
        .service
        .decide(u.tenant_id, id, u.id, u.role.as_str(), req)
        .await?;
    Ok(Json(row))
}

async fn cancel(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    s.service.cancel(u.tenant_id, id, u.id).await?;
    Ok(Json(serde_json::json!({ "cancelled": true })))
}
