//! Portal HTTP routes.
//!
//! Layout intentionally mirrors `auth/routes.rs` so a reader who knows
//! the agent surface can navigate this one. The router returned here
//! is meant to be mounted at `/api/v1/portal` and wrapped in
//! `portal_auth_middleware`.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::middleware::{portal_auth_middleware, PortalAuthMiddleware, RequirePortalAuth};
use super::service::PortalAuthService;
use super::{
    CreatePortalTicketRequest, CurrentContact, PortalLoginRequest, PortalLoginResponse,
};
use crate::modules::tickets::{TicketResponse, TicketService};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct PortalRouterState {
    pub service: Arc<PortalAuthService>,
    pub tickets: Arc<TicketService>,
}

/// Build the `/api/v1/portal` router. Wires the portal auth middleware
/// at the outermost layer so every handler sees either a valid
/// `PortalAuthState` or the default (unauthenticated) one.
pub fn portal_routes(service: PortalAuthService, tickets: TicketService) -> Router {
    let state = PortalRouterState {
        service: Arc::new(service.clone()),
        tickets: Arc::new(tickets),
    };
    let mw = PortalAuthMiddleware::new(service);

    Router::new()
        // Public: login. No auth required to call this.
        .route("/auth/login", post(login))
        // Protected: profile + ticket creation. List + get arrive in
        // subsequent commits in this story.
        .route("/auth/me", get(me))
        .route("/tickets", get(list_tickets).post(create_ticket))
        .route("/tickets/{ticket_id}", get(get_ticket))
        .route("/invoices", get(list_invoices))
        .route("/invoices/{invoice_id}", get(get_invoice))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            mw,
            portal_auth_middleware,
        ))
}

async fn login(
    State(state): State<PortalRouterState>,
    Json(request): Json<PortalLoginRequest>,
) -> AppResult<Json<PortalLoginResponse>> {
    request.validate()?;
    let resp = state.service.login(&request).await?;
    Ok(Json(resp))
}

async fn me(RequirePortalAuth(contact): RequirePortalAuth) -> AppResult<Json<CurrentContact>> {
    Ok(Json(contact))
}

async fn list_invoices(
    RequirePortalAuth(_contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<serde_json::Value>>> {
    // Auth is enforced (RequirePortalAuth) so unauthenticated callers
    // still get 401 instead of an empty 200, but the read itself is a
    // stub until the billing module (PMS-33 story) lands. Returns an
    // empty page so the portal frontend can render its "no invoices
    // yet" empty state without a follow-up branch on 501.
    Ok(Json(PaginatedResponse::from_params(vec![], &pagination, 0)))
}

async fn get_invoice(
    RequirePortalAuth(_contact): RequirePortalAuth,
    Path(_invoice_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    // Same shape as list_invoices: 401 for unauth callers, 404 for
    // everyone else, until billing lands.
    Err(crate::utils::error::AppError::NotFound("Invoice".to_string()))
}

async fn get_ticket(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<TicketResponse>> {
    let resp = state
        .tickets
        .get_portal_ticket(contact.tenant_id, contact.company_id, ticket_id)
        .await?;
    Ok(Json(resp))
}

async fn list_tickets(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketResponse>>> {
    let (tickets, total) = state
        .tickets
        .list_portal_tickets(contact.tenant_id, contact.company_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        tickets,
        &pagination,
        total,
    )))
}

async fn create_ticket(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Json(request): Json<CreatePortalTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    request.validate()?;
    let resp = state
        .tickets
        .create_portal_ticket(
            contact.tenant_id,
            contact.company_id,
            contact.id,
            request.title,
            request.description,
            request.priority_id,
            request.type_id,
        )
        .await?;
    Ok(Json(resp))
}
