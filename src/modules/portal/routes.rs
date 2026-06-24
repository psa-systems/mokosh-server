//! Portal HTTP routes.
//!
//! Layout intentionally mirrors `auth/routes.rs` so a reader who knows
//! the agent surface can navigate this one. The router returned here
//! is meant to be mounted at `/api/v1/portal` and wrapped in
//! `portal_auth_middleware`.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::middleware::{portal_auth_middleware, PortalAuthMiddleware, RequirePortalAuth};
use super::service::PortalAuthService;
use super::{
    CreatePortalTicketNoteRequest, CreatePortalTicketRequest, CurrentContact, PortalLoginRequest,
    PortalLoginResponse, PortalSetupPasswordRequest,
};
use crate::modules::billing::{BillingService, InvoiceFilter, InvoiceResponse};
use crate::modules::knowledge_base::{KbArticleResponse, KbService};
use crate::modules::tickets::{TicketNoteResponse, TicketResponse, TicketService};
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
        // Public: redeem a setup token to set the initial portal password
        // (PMS-136). No auth: the customer is not yet a logged-in contact;
        // the single-use token IS the credential proving they own the link.
        .route("/auth/setup-password", post(setup_password))
        // Protected: profile + ticket creation. List + get arrive in
        // subsequent commits in this story.
        .route("/auth/me", get(me))
        .route("/tickets", get(list_tickets).post(create_ticket))
        .route("/tickets/{ticket_id}", get(get_ticket))
        // PMS-449: portal ticket comments. GET lists `note_type='public'`
        // notes (internal / resolution / time_entry are filtered server-
        // side). POST accepts a fresh contact-authored comment that the
        // service stamps with `created_by_contact_id` while keeping
        // `created_by_id` pointed at a fallback admin (the column is NOT
        // NULL; the FK is to `users`, not `contacts`).
        .route(
            "/tickets/{ticket_id}/notes",
            get(list_ticket_notes).post(create_ticket_note),
        )
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

/// Redeem a setup token and set the contact's portal password (PMS-136).
/// Returns 204 on success; the service maps a replayed token to 410 and an
/// expired/invalid one to 400.
async fn setup_password(
    State(state): State<PortalRouterState>,
    Json(request): Json<PortalSetupPasswordRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    state
        .service
        .setup_password(&request.token, &request.password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
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
    // SAFETY (PMS-285): `contact.tenant_id` is a verified claim from the portal
    // JWT (`RequirePortalAuth`), i.e. the caller's own authenticated tenant.
    // Portal runs on contact sessions, not `CurrentUser`, so it cannot use the
    // `TenantScoped` extractor; `from_trusted` is the sanctioned bridge (see the
    // KB feed note below for the full rationale).
    let (items, total) = state
        .billing
        .list_invoices(contact.tenant(), &filter, &pagination)
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
    // SAFETY (PMS-285): `contact.tenant_id` is a verified portal-JWT claim
    // (`RequirePortalAuth`), the caller's own authenticated tenant; portal
    // cannot use `TenantScoped`, so `from_trusted` is the sanctioned bridge
    // (see KB feed note below). The company scope is enforced in code afterward.
    let invoice = state
        .billing
        .get_invoice(contact.tenant(), invoice_id)
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
        .list_portal_articles_for_company(contact.tenant(), contact.company_id, &pagination)
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
    // SAFETY (PMS-261): `contact.tenant_id` and `contact.company_id` are
    // verified claims from the portal JWT (`RequirePortalAuth`), not user
    // input. Portal runs on contact sessions rather than `CurrentUser`, so it
    // cannot use the `TenantScoped` extractor; `from_trusted` is the sanctioned
    // bridge. `get_portal_ticket` scopes by both tenant and company, so a
    // contact can only read its own company's ticket within its own tenant.
    let resp = state
        .tickets
        .get_portal_ticket(contact.tenant(), contact.company_id, ticket_id)
        .await?;
    Ok(Json(resp))
}

async fn list_tickets(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketResponse>>> {
    // SAFETY (PMS-261): verified contact-JWT claims (`RequirePortalAuth`), not
    // user input; portal cannot use `TenantScoped`. `list_portal_tickets`
    // scopes by both tenant and company, so the feed is confined to the
    // contact's own company within its own tenant.
    let (tickets, total) = state
        .tickets
        .list_portal_tickets(contact.tenant(), contact.company_id, &pagination)
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
    // SAFETY (PMS-261): verified contact-JWT claims (`RequirePortalAuth`), not
    // user input; portal cannot use `TenantScoped`. `create_portal_ticket`
    // writes under `contact.tenant_id` / `contact.company_id`, so a contact can
    // only create a ticket inside its own company and tenant.
    let resp = state
        .tickets
        .create_portal_ticket(
            contact.tenant(),
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

/// PMS-449: list the public comments on one of the contact's own
/// company's tickets. Server-side filters by `note_type='public'` so
/// internal agent back-channel never leaks to the customer. Cross-
/// company access surfaces as 404 (same posture as `get_ticket`).
async fn list_ticket_notes(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(ticket_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketNoteResponse>>> {
    // SAFETY (PMS-261/PMS-449): verified contact-JWT claims, not user input.
    // The service scopes by both tenant and company, so a guessed ticket id
    // from another company yields the same 404 a missing one would.
    let (notes, total) = state
        .tickets
        .list_portal_ticket_notes(contact.tenant(), contact.company_id, ticket_id, &pagination)
        .await?;
    let responses: Vec<TicketNoteResponse> = notes
        .into_iter()
        .map(|n| TicketNoteResponse {
            id: n.id,
            note_type: n.note_type,
            content: n.content,
            is_email_sent: n.is_email_sent,
            created_by_id: n.created_by_id,
            created_by_name: n.created_by_name.unwrap_or_default(),
            created_by_contact_id: n.created_by_contact_id,
            created_at: n.created_at,
        })
        .collect();
    Ok(Json(PaginatedResponse::from_params(
        responses,
        &pagination,
        total,
    )))
}

/// PMS-449: portal contact adds a comment on one of their own
/// company's tickets. `note_type` is forced to `public` server-
/// side; the customer cannot accidentally write an internal note.
async fn create_ticket_note(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(ticket_id): Path<Uuid>,
    Json(request): Json<CreatePortalTicketNoteRequest>,
) -> AppResult<Json<TicketNoteResponse>> {
    request.validate()?;
    let note = state
        .tickets
        .create_portal_ticket_note(
            contact.tenant(),
            contact.company_id,
            contact.id,
            ticket_id,
            request.content,
        )
        .await?;
    Ok(Json(TicketNoteResponse {
        id: note.id,
        note_type: note.note_type,
        content: note.content,
        is_email_sent: note.is_email_sent,
        created_by_id: note.created_by_id,
        created_by_name: note.created_by_name.unwrap_or_default(),
        created_by_contact_id: note.created_by_contact_id,
        created_at: note.created_at,
    }))
}
