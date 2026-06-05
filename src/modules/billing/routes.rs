//! Billing HTTP routes. Endpoints land incrementally across PMS-33.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, put},
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
        .route(
            "/invoices/from-time-entries",
            axum::routing::post(create_invoice_from_time_entries),
        )
        .route(
            "/invoices/{invoice_id}",
            get(get_invoice).put(update_invoice),
        )
        .route("/payments", get(list_payments).post(create_payment))
        .route("/payments/{payment_id}", delete(delete_payment))
        .route(
            "/payment-gateways",
            get(list_payment_gateways).put(upsert_payment_gateway),
        )
        .route(
            "/payment-gateways/{provider}",
            delete(delete_payment_gateway),
        )
        .route("/tax-rates", get(list_tax_rates).post(create_tax_rate))
        .route(
            "/tax-rates/{id}",
            put(update_tax_rate).delete(delete_tax_rate),
        )
        .route("/tax-rates/lookup", get(lookup_tax_rate))
        .with_state(state)
}

async fn list_tax_rates(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TaxRateResponse>>> {
    let (rates, total) = state
        .service
        .list_tax_rates(user.tenant_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        rates,
        &pagination,
        total,
    )))
}

async fn create_tax_rate(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Json(request): Json<UpsertTaxRateRequest>,
) -> AppResult<Json<TaxRateResponse>> {
    request.validate()?;
    let r = state
        .service
        .create_tax_rate(user.tenant_id, &request)
        .await?;
    Ok(Json(r))
}

async fn update_tax_rate(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertTaxRateRequest>,
) -> AppResult<Json<TaxRateResponse>> {
    request.validate()?;
    let r = state
        .service
        .update_tax_rate(user.tenant_id, id, &request)
        .await?;
    Ok(Json(r))
}

async fn delete_tax_rate(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state.service.delete_tax_rate(user.tenant_id, id).await?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct LookupQuery {
    name: String,
}

async fn lookup_tax_rate(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    Query(q): Query<LookupQuery>,
) -> AppResult<Json<TaxRateResponse>> {
    let r = state
        .service
        .lookup_tax_rate(user.tenant_id, &q.name)
        .await?;
    Ok(Json(r))
}

async fn list_payment_gateways(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<PaymentGatewayConfigResponse>>> {
    let (gateways, total) = state
        .service
        .list_payment_gateways(user.tenant_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        gateways,
        &pagination,
        total,
    )))
}

async fn upsert_payment_gateway(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Json(request): Json<UpsertPaymentGatewayConfigRequest>,
) -> AppResult<Json<PaymentGatewayConfigResponse>> {
    request.validate()?;
    let g = state
        .service
        .upsert_payment_gateway(user.tenant_id, &request)
        .await?;
    Ok(Json(g))
}

async fn delete_payment_gateway(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Path(provider): Path<String>,
) -> AppResult<()> {
    let provider = GatewayProvider::from_str(&provider).ok_or_else(|| {
        crate::utils::error::AppError::BadRequest(format!("unknown provider {provider:?}"))
    })?;
    state
        .service
        .delete_payment_gateway(user.tenant_id, provider)
        .await?;
    Ok(())
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
    Ok(Json(PaginatedResponse::from_params(
        payments,
        &pagination,
        total,
    )))
}

async fn create_payment(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Json(request): Json<CreatePaymentRequest>,
) -> AppResult<Json<PaymentResponse>> {
    request.validate()?;
    let p = state
        .service
        .create_payment(user.tenant_id, &request)
        .await?;
    Ok(Json(p))
}

async fn delete_payment(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Path(payment_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .service
        .delete_payment(user.tenant_id, payment_id)
        .await?;
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
    let inv = state
        .service
        .create_invoice(user.tenant_id, &request)
        .await?;
    Ok(Json(inv))
}

/// PMS-33 core: generate an invoice from a company's billable time
/// entries. Lower-risk than overloading `POST /invoices` (whose body is
/// a fully-specified line set): this is a distinct, additive route with
/// its own DTO, so existing invoice-create callers are untouched.
async fn create_invoice_from_time_entries(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Json(request): Json<CreateInvoiceFromTimeEntriesRequest>,
) -> AppResult<Json<InvoiceResponse>> {
    request.validate()?;
    let inv = state
        .service
        .create_invoice_from_time_entries(user.tenant_id, &request)
        .await?;
    Ok(Json(inv))
}

async fn get_invoice(
    State(state): State<BillingRouterState>,
    RequireAuth(user): RequireAuth,
    _finance: RequireFinance,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<InvoiceResponse>> {
    let inv = state
        .service
        .get_invoice(user.tenant_id, invoice_id)
        .await?;
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
    Ok(Json(PaginatedResponse::from_params(
        invoices,
        &pagination,
        total,
    )))
}
