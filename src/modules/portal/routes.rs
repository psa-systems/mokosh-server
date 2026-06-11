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
use super::{CreatePortalTicketRequest, CurrentContact, PortalLoginRequest, PortalLoginResponse};
use crate::modules::billing::{BillingService, InvoiceFilter, InvoiceResponse};
use crate::modules::knowledge_base::{KbArticleResponse, KbService};
use crate::modules::tickets::{TicketResponse, TicketService};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct PortalRouterState {
    pub service: Arc<PortalAuthService>,
    pub tickets: Arc<TicketService>,
    pub kb: Arc<KbService>,
    pub billing: Arc<BillingService>,
}

/// Build the `/api/v1/portal` router. Wires the portal auth middleware
/// at the outermost layer so every handler sees either a valid
/// `PortalAuthState` or the default (unauthenticated) one.
pub fn portal_routes(
    service: PortalAuthService,
    tickets: TicketService,
    kb: KbService,
    billing: BillingService,
) -> Router {
    let state = PortalRouterState {
        service: Arc::new(service.clone()),
        tickets: Arc::new(tickets),
        kb: Arc::new(kb),
        billing: Arc::new(billing),
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
        .route("/kb", get(list_kb))
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
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<InvoiceResponse>>> {
    // PMS-33 has landed: serve the contact's company invoices. The
    // company scope is forced from the authenticated `CurrentContact`
    // (never a query param), so a contact only ever sees its own
    // company's invoices.
    let filter = InvoiceFilter {
        company_id: Some(contact.company_id),
        ..Default::default()
    };
    // PMS-139: bridge the verified contact-JWT tenant through `from_trusted`
    // (portal runs on contact sessions, not `CurrentUser`; see the KB feed
    // note below for the full rationale).
    let (items, total) = state
        .billing
        .list_invoices(
            crate::modules::auth::TenantId::from_trusted(contact.tenant_id),
            &filter,
            &pagination,
        )
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_invoice(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<InvoiceResponse>> {
    // Read within the contact's tenant, then enforce the company scope
    // in code: an invoice belonging to another company in the same
    // tenant returns 404 (not 403) so the portal never confirms the
    // existence of another company's invoice.
    // PMS-139: bridge the verified contact-JWT tenant (see KB feed note below).
    let invoice = state
        .billing
        .get_invoice(
            crate::modules::auth::TenantId::from_trusted(contact.tenant_id),
            invoice_id,
        )
        .await?;
    if invoice.company_id != contact.company_id {
        return Err(crate::utils::error::AppError::NotFound(
            "Invoice".to_string(),
        ));
    }
    Ok(Json(invoice))
}

async fn list_kb(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbArticleResponse>>> {
    // Portal-visible KB feed (PMS-79 / PMS-84). Returns only
    // `status = 'published'` articles that are `visibility = 'public'`
    // OR `client_specific` with the caller's company listed in
    // `company_ids`. The company scope comes from the authenticated
    // contact's JWT claim (`CurrentContact.company_id`), populated by
    // `portal_auth_middleware`, so a client cannot widen it.
    // SAFETY (PMS-139): `contact.tenant_id` is a verified claim from the
    // portal JWT (`RequirePortalAuth`), not user input. Portal runs on
    // contact sessions rather than `CurrentUser`, so it cannot use the
    // `TenantScoped` extractor; `from_trusted` is the sanctioned bridge
    // until the portal surface gets its own scoping pass.
    let (items, total) = state
        .kb
        .list_portal_articles_for_company(
            crate::modules::auth::TenantId::from_trusted(contact.tenant_id),
            contact.company_id,
            &pagination,
        )
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_ticket(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<TicketResponse>> {
    let resp = state
        .tickets
        .get_portal_ticket(
            crate::modules::auth::TenantId::from_trusted(contact.tenant_id),
            contact.company_id,
            ticket_id,
        )
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
        .list_portal_tickets(
            crate::modules::auth::TenantId::from_trusted(contact.tenant_id),
            contact.company_id,
            &pagination,
        )
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
            crate::modules::auth::TenantId::from_trusted(contact.tenant_id),
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
