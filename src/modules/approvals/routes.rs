//! PMS-451 phase 1 + PMS-470 phase 2 + PMS-484: HTTP routes for approvals.
//!
//! Phase 1 mounted `/tickets/{ticket_id}/approvals`. Phase 2 added
//! `/time-entries/{entity_id}/approvals`. PMS-484 fleshes out the
//! remaining two prefixes - `/change-requests/...` and `/quotes/...` -
//! now that migration 078 ships the minimal `change_requests` and
//! `quotes` parent tables `assert_parent_exists` needs.
//!
//! PMS-944 draws a line through the four targets. A `change_request` and a
//! `quote` approve a DECISION, and a client asking for sign-off on a quote has
//! nothing to do with employment, so those are untouched. A `time_entry`
//! approves a unit of WORK, which is the employee-facing control David asked to
//! confine to timesheets, so both of its routes sit behind `RequireTimesheets`.
//! A `ticket` needed no change: nothing about a ticket is blocked by an
//! approval - `tickets` has no approval column, and `ApprovalsService::decide`
//! writes only its own table - so the sign-off is offered, never required, and
//! removing it would delete a working feature rather than a gate.

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
use crate::modules::auth::{RequireAuth, RequireTimesheets};
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
        // PMS-470 + PMS-484: polymorphic per-entity prefixes. The
        // handler resolves the prefix into an `ApprovalTarget` and
        // funnels into the same service surface. All four parent
        // tables (tickets, time_entries, change_requests, quotes) are
        // live as of PMS-484 migration 078.
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
///
/// PMS-944: behind `RequireTimesheets`. Approving a unit of work is an
/// employee-facing control, so it exists where timesheets do and nowhere else.
/// A one-person MSP has the flag off (PMS-943) and gets a 404 here, which is
/// what "no approval step exists at all" has to mean for a route: not an empty
/// list, which would read as a feature that is present and unused.
async fn list_for_time_entry(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    _timesheets: RequireTimesheets,
    Path(entity_id): Path<Uuid>,
) -> AppResult<Json<Vec<ApprovalResponse>>> {
    assert_parent_exists(&s, "time_entries", "Time entry", u.tenant_id, entity_id).await?;
    let rows = s
        .service
        .list_for_entity(u.tenant_id, ApprovalTarget::TimeEntry, entity_id)
        .await?;
    Ok(Json(rows))
}

/// PMS-944: behind `RequireTimesheets`, for the reason on `list_for_time_entry`.
/// This is the one that matters, because it is the only way a time-entry
/// approval can come into existence.
async fn create_for_time_entry(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    _timesheets: RequireTimesheets,
    Path(entity_id): Path<Uuid>,
    Json(req): Json<CreateApprovalRequest>,
) -> AppResult<Json<ApprovalResponse>> {
    req.validate().map_err(AppError::from)?;
    assert_parent_exists(&s, "time_entries", "Time entry", u.tenant_id, entity_id).await?;
    let row = s
        .service
        .create_for_entity(u.tenant_id, ApprovalTarget::TimeEntry, entity_id, u.id, req)
        .await?;
    Ok(Json(row))
}

/// PMS-484: list approvals on a change_request. Tenant-scoped via the
/// `change_requests` lookup so a guessed UUID returns 404 instead of
/// an empty 200 (mirrors the ticket / time_entry route posture).
async fn list_for_change_request(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(entity_id): Path<Uuid>,
) -> AppResult<Json<Vec<ApprovalResponse>>> {
    assert_parent_exists(
        &s,
        "change_requests",
        "Change request",
        u.tenant_id,
        entity_id,
    )
    .await?;
    let rows = s
        .service
        .list_for_entity(u.tenant_id, ApprovalTarget::ChangeRequest, entity_id)
        .await?;
    Ok(Json(rows))
}

async fn create_for_change_request(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(entity_id): Path<Uuid>,
    Json(req): Json<CreateApprovalRequest>,
) -> AppResult<Json<ApprovalResponse>> {
    req.validate().map_err(AppError::from)?;
    assert_parent_exists(
        &s,
        "change_requests",
        "Change request",
        u.tenant_id,
        entity_id,
    )
    .await?;
    let row = s
        .service
        .create_for_entity(
            u.tenant_id,
            ApprovalTarget::ChangeRequest,
            entity_id,
            u.id,
            req,
        )
        .await?;
    Ok(Json(row))
}

/// PMS-484: list approvals on a quote. Same posture as change_request.
async fn list_for_quote(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(entity_id): Path<Uuid>,
) -> AppResult<Json<Vec<ApprovalResponse>>> {
    assert_parent_exists(&s, "quotes", "Quote", u.tenant_id, entity_id).await?;
    let rows = s
        .service
        .list_for_entity(u.tenant_id, ApprovalTarget::Quote, entity_id)
        .await?;
    Ok(Json(rows))
}

async fn create_for_quote(
    State(s): State<ApprovalsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(entity_id): Path<Uuid>,
    Json(req): Json<CreateApprovalRequest>,
) -> AppResult<Json<ApprovalResponse>> {
    req.validate().map_err(AppError::from)?;
    assert_parent_exists(&s, "quotes", "Quote", u.tenant_id, entity_id).await?;
    let row = s
        .service
        .create_for_entity(u.tenant_id, ApprovalTarget::Quote, entity_id, u.id, req)
        .await?;
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

/// PMS-470: tenant-scoped existence check on a parent table.
/// Surfaces 404 when the row is absent in the caller's tenant so a
/// guessed UUID never leaks "I have an approval against an id you
/// can't see" via a 200 with empty body.
async fn assert_parent_exists(
    s: &ApprovalsRouterState,
    table: &'static str,
    noun: &'static str,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> AppResult<()> {
    // PMS-683: run the parent-existence check inside a tenant-GUC transaction
    // so it stays correct now that the checked tables (`time_entries`,
    // `change_requests`, `quotes`) are under fail-closed RLS. A raw-pool read
    // would match no rows once RLS is enabled.
    let mut tx = s.service.db().begin_with_tenant(tenant_id).await?;
    let exists: Option<(Uuid,)> = sqlx::query_as(&format!(
        "SELECT id FROM {table} WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(entity_id)
    .fetch_optional(&mut *tx)
    .await?;
    if exists.is_none() {
        // The message names the human noun, not `table`: the raw table name
        // reached the client as `time_entries not found ...` (PMS-775).
        return Err(AppError::NotFound(noun.to_string()));
    }
    Ok(())
}
