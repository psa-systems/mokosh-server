//! Portal HTTP routes.
//!
//! Layout intentionally mirrors `auth/routes.rs` so a reader who knows
//! the agent surface can navigate this one. The router returned here
//! is meant to be mounted at `/api/v1/portal` and wrapped in
//! `portal_auth_middleware`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::middleware::{portal_auth_middleware, PortalAuthMiddleware, RequirePortalAuth};
use super::rate_limit::{PortalDecisionLimiter, PortalLoginLimiter};
use super::service::{token_contact_id, PortalAuthService};
use super::{
    CreatePortalTicketNoteRequest, CreatePortalTicketRequest, CurrentContact,
    PortalForgotPasswordRequest, PortalLoginRequest, PortalResetPasswordRequest,
    PortalSetupPasswordRequest,
};
use crate::modules::auth::rate_limit::AuthRateLimiter;
use crate::modules::billing::{BillingService, InvoiceFilter, InvoiceResponse, PayInvoiceResponse};
use crate::modules::knowledge_base::{KbArticleResponse, KbService};
use crate::modules::quotes::{
    ClientDecision, PortalQuoteDecisionRequest, QuoteResponse, QuotesService,
};
use crate::modules::tickets::{TicketNoteResponse, TicketResponse, TicketService};
use crate::utils::error::{rate_limited_response, AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct PortalRouterState {
    pub service: Arc<PortalAuthService>,
    pub tickets: Arc<TicketService>,
    pub kb: Arc<KbService>,
    pub billing: Arc<BillingService>,
    pub quotes: Arc<QuotesService>,
    /// Layered (per-IP + per-(tenant_slug, email)) login rate limiter
    /// (PMS-501). Lives for the lifetime of the router so quota state
    /// survives across requests. The check runs inline at the top of the
    /// `login` handler so the limiter can see both source IP and the
    /// `(tenant_slug, email)` from the deserialized request body.
    pub login_limiter: Arc<PortalLoginLimiter>,
    /// PMS-673: throttles the quote accept / decline routes. Separate from
    /// `login_limiter` so a burst of decisions cannot lock a contact out of
    /// logging back in.
    pub decision_limiter: Arc<PortalDecisionLimiter>,
    /// PMS-820: throttles `/auth/forgot-password`, per IP and per
    /// `(tenant_slug, email)`. Its own instance with its own buckets, so a
    /// reset request never consumes login quota (and vice versa) - the same
    /// per-endpoint split PMS-680 made on the platform side.
    pub forgot_password_limiter: Arc<AuthRateLimiter>,
    /// PMS-820: throttles `/auth/reset-password`, per IP and per contact.
    /// The account bucket keys on the contact id carried in the token
    /// because that body has no email in it; a malformed token keys on the
    /// IP bucket alone.
    pub reset_password_limiter: Arc<AuthRateLimiter>,
    /// PMS-711: SPA origin the invoice "Pay Now" success / cancel return URLs
    /// are built from (the base of the portal invoice pages).
    pub portal_origin: String,
}

/// Build the `/api/v1/portal` router. Wires the portal auth middleware
/// at the outermost layer so every handler sees either a valid
/// `PortalAuthState` or the default (unauthenticated) one.
pub fn portal_routes(
    service: PortalAuthService,
    tickets: TicketService,
    kb: KbService,
    billing: BillingService,
    quotes: QuotesService,
    portal_origin: String,
) -> Router {
    let state = PortalRouterState {
        service: Arc::new(service.clone()),
        tickets: Arc::new(tickets),
        kb: Arc::new(kb),
        billing: Arc::new(billing),
        quotes: Arc::new(quotes),
        login_limiter: PortalLoginLimiter::new(),
        decision_limiter: PortalDecisionLimiter::new(),
        // PMS-820, matching the platform forgot-password numbers (PMS-680):
        // 10/min per IP, 3/min per account - enough for a fumbling customer,
        // and it caps reset-mail bombing of a known address.
        forgot_password_limiter: AuthRateLimiter::new(10, 3),
        reset_password_limiter: AuthRateLimiter::new(10, 3),
        portal_origin,
    };
    let mw = PortalAuthMiddleware::new(service);

    Router::new()
        // Public: login. No auth required to call this.
        .route("/auth/login", post(login))
        // Public: redeem a setup token to set the initial portal password
        // (PMS-136). No auth: the customer is not yet a logged-in contact;
        // the single-use token IS the credential proving they own the link.
        .route("/auth/setup-password", post(setup_password))
        // Public: portal-scoped self-service password reset (PMS-820). The
        // portal's own path, resolving the identity from `contacts` inside
        // the requested tenant; the platform `/auth/forgot-password` route
        // resolves against `users` and the two can never cross, however many
        // identities one email address holds.
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password", post(reset_password))
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
        // PMS-711: client-facing "Pay Now". Mints a provider checkout session
        // for the invoice balance and returns its URL for the SPA to redirect
        // to. Company-scoped exactly like `get_invoice`.
        .route("/invoices/{invoice_id}/pay", post(pay_invoice))
        // PMS-673: client-facing quote sign-off. Reads are scoped to the
        // contact's own company and to statuses that were actually issued;
        // accept / decline are the client's decision and are the only way
        // a quote reaches `accepted` / `declined`.
        .route("/quotes", get(list_quotes))
        .route("/quotes/{quote_id}", get(get_quote))
        .route("/quotes/{quote_id}/accept", post(accept_quote))
        .route("/quotes/{quote_id}/decline", post(decline_quote))
        .route("/kb", get(list_kb))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            mw,
            portal_auth_middleware,
        ))
}

/// Portal login. Rate-limited per `(source IP, (tenant_slug, lowercased
/// email))` at 20/min per IP + 5/min per account; over-quota returns 429
/// with a `Retry-After` header (PMS-501). The check runs inline because
/// tower middleware cannot read the JSON body without buffering it. A
/// persistent failed-attempt lockout lives in `PortalAuthService::login`
/// and surfaces here as `AppError::RateLimited` (429) as well - deliberately
/// without a wait, unlike its MFA counterpart: the caller has proved nothing
/// about the account, so the window would confirm the address exists.
async fn login(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<PortalLoginRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    if let Err(retry_after) =
        state
            .login_limiter
            .check(addr.ip(), &request.tenant_slug, &request.email)
    {
        return Ok(rate_limited_response(
            retry_after,
            "Too many login attempts, please try again later",
        ));
    }

    let resp = state.service.login(&request).await?;
    Ok(Json(resp).into_response())
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

/// PMS-820: start a portal password reset. Always answers 200 with an empty
/// body, whether or not the address belongs to a portal contact, so the
/// endpoint cannot be used to enumerate a tenant's customers. Rate-limited
/// inline (like login) because the email lives in the request body.
async fn forgot_password(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<PortalForgotPasswordRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    // Key the account bucket on `(tenant_slug, email)`, not the bare email:
    // two tenants can legitimately host the same customer address and must
    // not share one quota.
    if let Err(retry_after) = state.forgot_password_limiter.check(
        addr.ip(),
        &account_key(&request.tenant_slug, &request.email),
    ) {
        return Ok(rate_limited_response(
            retry_after,
            "Too many password reset requests, please try again later",
        ));
    }

    state
        .service
        .request_password_reset(&request.tenant_slug, &request.email)
        .await?;
    Ok(StatusCode::OK.into_response())
}

/// PMS-820: redeem a portal reset token and set the contact's password.
/// Same status contract as `setup_password` (204 / 410 on replay / 400 on
/// an expired, unknown or malformed token) because it is the same
/// contact-bound single-use token.
async fn reset_password(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<PortalResetPasswordRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    // The body carries no email, so the account bucket keys on the contact
    // the token names. A malformed token has no contact to key on and rides
    // the per-IP bucket alone.
    let account = token_contact_id(&request.token)
        .map(|id| id.to_string())
        .unwrap_or_default();
    if let Err(retry_after) = state.reset_password_limiter.check(addr.ip(), &account) {
        return Ok(rate_limited_response(
            retry_after,
            "Too many password reset attempts, please try again later",
        ));
    }

    state
        .service
        .reset_password(&request.token, &request.password)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Normalised `(tenant_slug, email)` rate-limit bucket key. A NUL byte
/// separates the halves so `("ab", "c")` and `("a", "bc")` never collide;
/// `AuthRateLimiter` trims and lowercases what it is handed.
fn account_key(tenant_slug: &str, email: &str) -> String {
    format!("{}\u{0}{}", tenant_slug.trim(), email.trim())
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

/// PMS-711: client-facing "Pay Now". Mints a provider checkout session for the
/// invoice's outstanding balance and returns its URL. The company scope is
/// enforced first (a cross-company invoice is a 404, same posture as
/// `get_invoice`); the service then rejects a void / fully-paid invoice or a
/// tenant with no active gateway.
async fn pay_invoice(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<PayInvoiceResponse>> {
    // SAFETY (PMS-285): `contact.tenant()` wraps a verified portal-JWT claim,
    // the caller's own authenticated tenant. Portal runs on contact sessions,
    // not `CurrentUser`, so it cannot use `TenantScoped`; `from_trusted` is the
    // sanctioned bridge. The company scope is enforced in code below.
    let invoice = state
        .billing
        .get_invoice(contact.tenant(), invoice_id)
        .await?;
    if invoice.company_id != contact.company_id {
        return Err(AppError::NotFound("Invoice".to_string()));
    }

    let base = state.portal_origin.trim_end_matches('/');
    let success_url = format!("{base}/portal/invoices/{invoice_id}?paid=1");
    let cancel_url = format!("{base}/portal/invoices/{invoice_id}");
    let session = state
        .billing
        .create_invoice_checkout_session(contact.tenant(), invoice_id, &success_url, &cancel_url)
        .await?;
    Ok(Json(PayInvoiceResponse {
        checkout_url: session.url,
    }))
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

// ============================================================================
// PMS-673: client-facing quote sign-off.
// ============================================================================

async fn list_quotes(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<QuoteResponse>>> {
    // The company scope is forced from the authenticated `CurrentContact`,
    // never a query param, so a contact only ever sees its own company's
    // quotes. The service further restricts to issued statuses.
    // SAFETY (PMS-285): `contact.tenant()` wraps a verified portal-JWT
    // claim, the caller's own authenticated tenant; portal runs on contact
    // sessions rather than `CurrentUser`, so it cannot use `TenantScoped`
    // and `from_trusted` is the sanctioned bridge (see the invoice + KB
    // notes above).
    let (items, total) = state
        .quotes
        .list_quotes_for_company(contact.tenant(), contact.company_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_quote(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(quote_id): Path<Uuid>,
) -> AppResult<Json<QuoteResponse>> {
    // A quote belonging to another company, or one not yet issued, comes
    // back 404 rather than 403 so the portal never confirms that it
    // exists. Same posture as `get_invoice`.
    let quote = state
        .quotes
        .get_quote_for_company(contact.tenant(), contact.company_id, quote_id)
        .await?;
    Ok(Json(quote))
}

async fn accept_quote(
    state: State<PortalRouterState>,
    addr: ConnectInfo<SocketAddr>,
    auth: RequirePortalAuth,
    ctx: crate::modules::audit::AuditCtx,
    path: Path<Uuid>,
    body: Option<Json<PortalQuoteDecisionRequest>>,
) -> Result<Response, AppError> {
    decide(state, addr, auth, ctx, path, body, true).await
}

async fn decline_quote(
    state: State<PortalRouterState>,
    addr: ConnectInfo<SocketAddr>,
    auth: RequirePortalAuth,
    ctx: crate::modules::audit::AuditCtx,
    path: Path<Uuid>,
    body: Option<Json<PortalQuoteDecisionRequest>>,
) -> Result<Response, AppError> {
    decide(state, addr, auth, ctx, path, body, false).await
}

/// Shared body of accept / decline. The two routes differ only in the
/// outcome they record, so the rate-limit check, validation, and audit
/// context handling live in one place.
///
/// The JSON body is optional: accepting with nothing to say is the common
/// case, and requiring `{}` would be a needless 415 for that caller.
async fn decide(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    RequirePortalAuth(contact): RequirePortalAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(quote_id): Path<Uuid>,
    body: Option<Json<PortalQuoteDecisionRequest>>,
    accept: bool,
) -> Result<Response, AppError> {
    let request = body.map(|Json(b)| b).unwrap_or_default();
    request.validate()?;

    if let Err(retry_after) = state.decision_limiter.check(addr.ip(), contact.id) {
        return Ok(rate_limited_response(
            retry_after,
            "Too many quote decisions, please try again shortly",
        ));
    }

    let decision = ClientDecision {
        company_id: contact.company_id,
        contact_id: contact.id,
        accept,
        notes: request.notes,
    };
    let quote = state
        .quotes
        .decide_quote(contact.tenant(), quote_id, &decision, &ctx)
        .await?;
    Ok(Json(quote).into_response())
}
