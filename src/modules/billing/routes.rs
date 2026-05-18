//! Billing HTTP routes. Endpoints land incrementally across PMS-33.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::BillingService;
use crate::modules::auth::{RequireAuth, RequireFinance};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct BillingRouterState {
    pub service: Arc<BillingService>,
}

/// Build the billing router. URLs are absolute (`/invoices`, etc.) so
/// the call site `merge`s rather than `nest`s.
pub fn billing_routes(service: BillingService) -> Router {
    let state = BillingRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/invoices", get(list_invoices))
        .route("/invoices/{invoice_id}", get(get_invoice))
        .with_state(state)
}

async fn get_invoice(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<InvoiceResponse>> {
    let inv = state.service.get_invoice(user.tenant_id, invoice_id).await?;
    Ok(Json(inv))
}

async fn list_invoices(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Query(filter): Query<InvoiceFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<InvoiceResponse>>> {
    filter.validate()?;
    let (invoices, total) = state
        .service
        .list_invoices(user.tenant_id, &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(invoices, &pagination, total)))
}
