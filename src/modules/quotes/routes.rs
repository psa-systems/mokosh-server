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
use crate::modules::auth::{RequireBilling, RequireFinance, TenantScoped};
use crate::utils::error::AppResult;
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
        .route("/quotes/{quote_id}/lines", post(add_line))
        .route(
            "/quotes/{quote_id}/lines/{line_id}",
            axum::routing::put(update_line).delete(delete_line),
        )
        .with_state(state)
}

async fn list_quotes(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(filter): Query<QuoteFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<QuoteResponse>>> {
    filter.validate()?;
    let (quotes, total) = state
        .service
        .list_quotes(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        quotes,
        &pagination,
        total,
    )))
}

async fn get_quote(
    State(state): State<QuotesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(quote_id): Path<Uuid>,
) -> AppResult<Json<QuoteResponse>> {
    let quote = state.service.get_quote(user.tenant(), quote_id).await?;
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
