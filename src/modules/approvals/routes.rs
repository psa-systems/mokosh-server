//! PMS-451 phase 1 + PMS-470 phase 2: HTTP routes for approvals.
//!
//! Phase 1 mounted `/tickets/{ticket_id}/approvals`. Phase 2 keeps
//! that path identical and adds `/time-entries/{entity_id}/approvals`
//! (the only second parent table that exists today). Routes for
//! `/change-requests/...` and `/quotes/...` are wired but skip the
//! parent-existence check until those tables land - tracked under a
//! follow-up ticket so the server side is ready when the schemas
//! catch up.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::{
    ApprovalResponse, ApprovalTarget, CreateApprovalRequest, DecideApprovalRequest,
};
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
        // Phase-1 ticket-scoped surface. Preserved byte-identical so
        // existing consumers do not have to migrate.
        .route(
            "/tickets/{ticket_id}/approvals",
            get(list_for_ticket).post(create_for_ticket),
        )
        // PMS-470: polymorphic per-entity prefixes. The handler
        // resolves the prefix into an `ApprovalTarget` and funnels
        // into the same service surface. time_entries is the only
        // non-ticket parent table that exists today; the
        // change_request / quote handlers stay registered so the SPA
        // can adopt the URL shape early, but the parent-existence
        // check short-circuits to 501 until the parent tables land
        // (tracked under the PMS-470 follow-up).
        .route(
            "/time-entries/{entity_id}/approvals",
            get(list_for_time_entry).post(create_for_time_entry),
        )
        .route(
            "/change-requests/{entity_id}/approvals",
            get(list_for_change_request).post(create_for_change_request),
        )
        .route(
            "/quotes/{entity_id}/approvals",
            get(list_for_quote).post(create_for_quote),
        )
        // Caller's pending decision queue. PMS-470 widens it to span
        // every target; the response carries `target` + `entity_id`
        // so the SPA can render an entity link per row.
        .route("/approvals/pending", get(pending_for_caller))
        // Decision + cancel paths. Cancel is DELETE because the row
        // remains in the DB with status='cancelled'; matches the
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

/// PMS-470: list approvals on a time_entry. Tenant-scoped via the
/// `time_entries` lookup so a guessed UUID returns 404 instead of an
/// empty 200 (mirrors the ticket-route posture).
async fn list_for_time_entry(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(entity_id): Path<Uuid>,
) -> AppResult<Json<Vec<ApprovalResponse>>> {
    assert_parent_exists(&s, "time_entries", u.tenant_id, entity_id).await?;
    let rows = s
        .service
        .list_for_entity(u.tenant_id, ApprovalTarget::TimeEntry, entity_id)
        .await?;
    Ok(Json(rows))
}

async fn create_for_time_entry(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(entity_id): Path<Uuid>,
    Json(req): Json<CreateApprovalRequest>,
) -> AppResult<Json<ApprovalResponse>> {
    req.validate().map_err(AppError::from)?;
    assert_parent_exists(&s, "time_entries", u.tenant_id, entity_id).await?;
    let row = s
        .service
        .create_for_entity(u.tenant_id, ApprovalTarget::TimeEntry, entity_id, u.id, req)
        .await?;
    Ok(Json(row))
}

/// PMS-470 follow-up: change_requests parent table does not exist
/// yet. The route is mounted so the SPA can pin the URL shape but
/// it returns 501 until the schema catches up.
async fn list_for_change_request(
    State(_s): State<ApprovalsRouterState>,
    RequireAuth(_u): RequireAuth,
    Path(_entity_id): Path<Uuid>,
) -> AppResult<Json<Vec<ApprovalResponse>>> {
    Err(AppError::BadRequest(
        "change_requests parent table is not yet defined; tracked as a PMS-470 follow-up".into(),
    ))
}

async fn create_for_change_request(
    State(_s): State<ApprovalsRouterState>,
    RequireAuth(_u): RequireAuth,
    Path(_entity_id): Path<Uuid>,
    Json(_req): Json<CreateApprovalRequest>,
) -> AppResult<Json<ApprovalResponse>> {
    Err(AppError::BadRequest(
        "change_requests parent table is not yet defined; tracked as a PMS-470 follow-up".into(),
    ))
}

/// PMS-470 follow-up: same posture as change_requests.
async fn list_for_quote(
    State(_s): State<ApprovalsRouterState>,
    RequireAuth(_u): RequireAuth,
    Path(_entity_id): Path<Uuid>,
) -> AppResult<Json<Vec<ApprovalResponse>>> {
    Err(AppError::BadRequest(
        "quotes parent table is not yet defined; tracked as a PMS-470 follow-up".into(),
    ))
}

async fn create_for_quote(
    State(_s): State<ApprovalsRouterState>,
    RequireAuth(_u): RequireAuth,
    Path(_entity_id): Path<Uuid>,
    Json(_req): Json<CreateApprovalRequest>,
) -> AppResult<Json<ApprovalResponse>> {
    Err(AppError::BadRequest(
        "quotes parent table is not yet defined; tracked as a PMS-470 follow-up".into(),
    ))
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

/// PMS-470: tenant-scoped existence check on a parent table.
/// Surfaces 404 when the row is absent in the caller's tenant so a
/// guessed UUID never leaks "I have an approval against an id you
/// can't see" via a 200 with empty body.
async fn assert_parent_exists(
    s: &ApprovalsRouterState,
    table: &'static str,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> AppResult<()> {
    let exists: Option<(Uuid,)> = sqlx::query_as(&format!(
        "SELECT id FROM {table} WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(entity_id)
    .fetch_optional(s.service.pool())
    .await?;
    if exists.is_none() {
        return Err(AppError::NotFound(format!(
            "{table} not found in tenant scope"
        )));
    }
    Ok(())
}
