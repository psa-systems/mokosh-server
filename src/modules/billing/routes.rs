//! Billing HTTP routes. Endpoints land incrementally across PMS-33.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
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
        .route("/invoices", get(list_invoices).post(create_invoice))
        .route("/invoices/{invoice_id}", get(get_invoice).put(update_invoice))
        .route("/payments", get(list_payments).post(create_payment))
        .route("/payments/{payment_id}", delete(delete_payment))
        .with_state(state)
}

async fn list_payments(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Query(filter): Query<PaymentFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<PaymentResponse>>> {
    filter.validate()?;
    let (payments, total) = state
        .service
        .list_payments(user.tenant_id, &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(payments, &pagination, total)))
}

async fn create_payment(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Json(request): Json<CreatePaymentRequest>,
) -> AppResult<Json<PaymentResponse>> {
    request.validate()?;
    let p = state.service.create_payment(user.tenant_id, &request).await?;
    Ok(Json(p))
}

async fn delete_payment(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Path(payment_id): Path<Uuid>,
) -> AppResult<()> {
    state.service.delete_payment(user.tenant_id, payment_id).await?;
    Ok(())
}

async fn update_invoice(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Path(invoice_id): Path<Uuid>,
    Json(request): Json<UpdateInvoiceRequest>,
) -> AppResult<Json<InvoiceResponse>> {
    request.validate()?;
    let inv = state
        .service
        .update_invoice(user.tenant_id, invoice_id, &request)
        .await?;
    Ok(Json(inv))
}

async fn create_invoice(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Json(request): Json<CreateInvoiceRequest>,
) -> AppResult<Json<InvoiceResponse>> {
    request.validate()?;
    let inv = state.service.create_invoice(user.tenant_id, &request).await?;
    Ok(Json(inv))
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
