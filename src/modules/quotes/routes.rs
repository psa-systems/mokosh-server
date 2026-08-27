//! Quotes HTTP routes (PMS-672).
//!
//! RBAC mirrors the other money-bearing surfaces exactly rather than
//! inventing a policy: the `billing` module gate plus `RequireFinance`,
//! the same pair `invoices`, `contracts`, and `rate-cards` use. PMS-350
//! established that every financial surface is finance-gated on reads as
//! well as writes, and a quote is a priced commercial document, so it
//! belongs in that set. `tests/rbac_route_coverage.rs` pins it.
//!
//! URLs are absolute (`/quotes`, ...) so the call site `merge`s rather
//! than `nest`s, matching `billing_routes`. That also keeps
//! `/quotes/{id}/approvals` (owned by `modules::approvals`) sitting
//! alongside these paths under the same prefix.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::QuotesService;
use crate::db::Database;
use crate::modules::auth::{
    CallerContext, RequireBilling, RequireCallerContext, RequireFinance, TenantScoped,
};
use crate::modules::contact_portal::capabilities as caps;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct QuotesRouterState {
    pub service: Arc<QuotesService>,
}

pub fn quotes_routes(service: QuotesService) -> Router {
    let state = QuotesRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/quotes", get(list_quotes).post(create_quote))
        .route(
            "/quotes/{quote_id}",
            get(get_quote).put(update_quote).delete(cancel_quote),
        )
        // PMS-673: issue the approved quote to the client. Internal
        // sign-off stays on the existing `/quotes/{id}/approvals`
        // surface, which this module does not touch.
        .route("/quotes/{quote_id}/send", post(send_quote))
        // PMS-674: the accepted quote becomes the Project the MSP works.
        .route("/quotes/{quote_id}/convert", post(convert_quote))
        // mokosh-contact-login prompt 008: contact-plane accept /
        // decline endpoints. Gates on quotes:accept; scopes to the
        // caller's Company (foreign quote 404s, not 403s).
        .route("/quotes/{quote_id}/accept", post(accept_quote))
        .route("/quotes/{quote_id}/decline", post(decline_quote))
        // PMS-936: contact- and staff-callable quote PDF surface.
        // Contact plane gates on `quotes:download_pdf`; server-side
        // PDF generation is deferred to a follow-up ticket so the
        // handler currently returns 501 with a helpful message. The
        // capability gate is the load-bearing piece of the ticket.
        .route("/quotes/{quote_id}/pdf", get(get_quote_pdf))
        .route("/quotes/{quote_id}/lines", post(add_line))
        .route(
            "/quotes/{quote_id}/lines/{line_id}",
            axum::routing::put(update_line).delete(delete_line),
        )
        .with_state(state)
}

async fn list_quotes(
    State(state): State<QuotesRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Query(mut filter): Query<QuoteFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<QuoteResponse>>> {
    filter.validate()?;
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => assert_staff_billing_finance(auth)?,
        CallerContext::Contact(session) => {
            caller.require_capability(caps::QUOTES_READ, &db).await?;
            filter.company_id = Some(session.company_id);
        }
    }
    let (quotes, total) = state
        .service
        .list_quotes(tenant, &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        quotes,
        &pagination,
        total,
    )))
}

async fn get_quote(
    State(state): State<QuotesRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(quote_id): Path<Uuid>,
) -> AppResult<Json<QuoteResponse>> {
    match &caller {
        CallerContext::Staff(auth) => assert_staff_billing_finance(auth)?,
        CallerContext::Contact(_) => {
            caller.require_capability(caps::QUOTES_READ, &db).await?;
        }
    }
    let quote = state.service.get_quote(caller.tenant(), quote_id).await?;
    if let CallerContext::Contact(session) = &caller {
        // mokosh-contact-login prompt 008: 404 (not 403) on a foreign
        // Company so a contact cannot probe for another Company's
        // quote ids.
        if quote.company_id != session.company_id {
            return Err(AppError::NotFound("Quote".to_string()));
        }
    }
    Ok(Json(quote))
}

/// mokosh-contact-login prompt 008: reproduce the RequireBilling +
/// RequireFinance staff gate inline for a handler that now takes
/// `RequireCallerContext`. Mirrors the same helper on the billing
/// routes; the intentional duplication keeps each module's failure
/// mode locally auditable.
fn assert_staff_billing_finance(auth: &crate::modules::auth::AuthState) -> AppResult<()> {
    let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
    let role = user.role.as_str();
    if !matches!(role, "super_admin" | "admin" | "finance") {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }
    Ok(())
}

/// PMS-936: dual-plane quote PDF endpoint. Contact caller gates on
/// `quotes:download_pdf` + Company scope; staff caller keeps the
/// RequireBilling + RequireFinance inline check. Actual PDF rendering
/// is deferred to a follow-up ticket - the response is 501 with a
/// helpful message once every authz gate passes. The cap gate is what
/// matters for this ticket.
async fn get_quote_pdf(
    State(state): State<QuotesRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(quote_id): Path<Uuid>,
) -> AppResult<axum::response::Response> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    match &caller {
        CallerContext::Staff(auth) => assert_staff_billing_finance(auth)?,
        CallerContext::Contact(_) => {
            caller
                .require_capability(caps::QUOTES_DOWNLOAD_PDF, &db)
                .await?;
        }
    }
    let quote = state.service.get_quote(caller.tenant(), quote_id).await?;
    if let CallerContext::Contact(session) = &caller {
        if quote.company_id != session.company_id {
            return Err(AppError::NotFound("Quote".to_string()));
        }
    }
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "quote PDF download is not yet wired; see PMS-936 follow-up",
    )
        .into_response())
}

/// mokosh-contact-login prompt 008: contact-plane accept endpoint.
/// Gates on quotes:accept, then delegates to the shared decision
/// path so the state-machine invariants (valid_until check, single-
/// decision guard) live in one place.
#[derive(Debug, Clone, serde::Deserialize)]
struct QuoteDecisionBody {
    #[serde(default)]
    notes: Option<String>,
}

async fn accept_quote(
    State(state): State<QuotesRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    ctx: crate::modules::audit::AuditCtx,
    Path(quote_id): Path<Uuid>,
    body: Option<Json<QuoteDecisionBody>>,
) -> AppResult<Json<QuoteResponse>> {
    contact_decide(&state, &caller, &db, quote_id, true, body, &ctx).await
}

async fn decline_quote(
    State(state): State<QuotesRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    ctx: crate::modules::audit::AuditCtx,
    Path(quote_id): Path<Uuid>,
    body: Option<Json<QuoteDecisionBody>>,
) -> AppResult<Json<QuoteResponse>> {
    contact_decide(&state, &caller, &db, quote_id, false, body, &ctx).await
}

async fn contact_decide(
    state: &QuotesRouterState,
    caller: &CallerContext,
    db: &Database,
    quote_id: Uuid,
    accept: bool,
    body: Option<Json<QuoteDecisionBody>>,
    ctx: &crate::modules::audit::AuditCtx,
) -> AppResult<Json<QuoteResponse>> {
    // Contact-plane only for now: staff sign-off happens via the
    // existing `/quotes/{id}/approvals` surface which this sweep does
    // not touch. A staff bearer hitting accept / decline gets 403 so
    // the semantics stay explicit.
    let session = match caller {
        CallerContext::Contact(session) => session,
        CallerContext::Staff(_) => {
            return Err(AppError::Forbidden(
                "Staff use the approvals endpoint, not accept/decline.".to_string(),
            ));
        }
    };
    caller.require_capability(caps::QUOTES_ACCEPT, db).await?;
    let notes = body.and_then(|Json(b)| b.notes);
    let decision = ClientDecision {
        company_id: session.company_id,
        accept,
        contact_id: session.id,
        notes,
    };
    let quote = state
        .service
        .decide_quote(caller.tenant(), quote_id, &decision, ctx)
        .await?;
    Ok(Json(quote))
}

async fn create_quote(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateQuoteRequest>,
) -> AppResult<Json<QuoteResponse>> {
    request.validate()?;
    let quote = state
        .service
        .create_quote(user.tenant(), user.id, &request, &ctx)
        .await?;
    Ok(Json(quote))
}

async fn update_quote(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(quote_id): Path<Uuid>,
    Json(request): Json<UpdateQuoteRequest>,
) -> AppResult<Json<QuoteResponse>> {
    request.validate()?;
    let quote = state
        .service
        .update_quote(user.tenant(), quote_id, &request, &ctx)
        .await?;
    Ok(Json(quote))
}

/// `DELETE /quotes/{id}` cancels rather than deletes; see
/// [`QuotesService::cancel_quote`].
async fn cancel_quote(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(quote_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .service
        .cancel_quote(user.tenant(), quote_id, &ctx)
        .await?;
    Ok(())
}

async fn add_line(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(quote_id): Path<Uuid>,
    Json(request): Json<QuoteLineRequest>,
) -> AppResult<Json<QuoteResponse>> {
    request.validate()?;
    let quote = state
        .service
        .add_line(user.tenant(), quote_id, &request)
        .await?;
    Ok(Json(quote))
}

async fn update_line(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path((quote_id, line_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<QuoteLineRequest>,
) -> AppResult<Json<QuoteResponse>> {
    request.validate()?;
    let quote = state
        .service
        .update_line(user.tenant(), quote_id, line_id, &request)
        .await?;
    Ok(Json(quote))
}

async fn delete_line(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path((quote_id, line_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<QuoteResponse>> {
    let quote = state
        .service
        .delete_line(user.tenant(), quote_id, line_id)
        .await?;
    Ok(Json(quote))
}

/// Send an approved quote to the client (PMS-673). 409 unless the quote
/// is internally `approved`; see [`QuotesService::send_quote`].
async fn send_quote(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(quote_id): Path<Uuid>,
) -> AppResult<Json<QuoteResponse>> {
    let quote = state
        .service
        .send_quote(user.tenant(), quote_id, &ctx)
        .await?;
    Ok(Json(quote))
}

/// Convert an accepted quote into a Project (PMS-674).
///
/// 409 unless the client has accepted. Converting an already-converted
/// quote is not an error: it returns the same `converted_project_id`, so
/// a double-clicked Convert button cannot produce two projects. The body
/// is optional because every field on it is.
async fn convert_quote(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(quote_id): Path<Uuid>,
    body: Option<Json<ConvertQuoteRequest>>,
) -> AppResult<Json<QuoteResponse>> {
    let request = body.map(|Json(b)| b).unwrap_or_default();
    request.validate()?;
    let quote = state
        .service
        .convert_quote(user.tenant(), quote_id, &request, &ctx)
        .await?;
    Ok(Json(quote))
}
