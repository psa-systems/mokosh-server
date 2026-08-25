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
use crate::db::Database;
use crate::modules::auth::{
    CallerContext, RequireBilling, RequireCallerContext, RequireFinance, TenantScoped,
};
use crate::modules::contact_portal::capabilities as caps;
use crate::utils::error::{AppError, AppResult};
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
        .route(
            "/payment-terms",
            get(list_payment_terms).post(create_payment_term),
        )
        .route(
            "/payment-terms/{id}",
            put(update_payment_term).delete(delete_payment_term),
        )
        .with_state(state)
}

async fn list_payment_terms(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<PaymentTermResponse>>> {
    let (terms, total) = state
        .service
        .list_payment_terms(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        terms,
        &pagination,
        total,
    )))
}

async fn create_payment_term(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertPaymentTermRequest>,
) -> AppResult<Json<PaymentTermResponse>> {
    request.validate()?;
    let t = state
        .service
        .create_payment_term(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(t))
}

async fn update_payment_term(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertPaymentTermRequest>,
) -> AppResult<Json<PaymentTermResponse>> {
    request.validate()?;
    let t = state
        .service
        .update_payment_term(user.tenant(), id, &request)
        .await?;
    Ok(Json(t))
}

async fn delete_payment_term(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state.service.delete_payment_term(user.tenant(), id).await?;
    Ok(())
}

async fn list_tax_rates(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TaxRateResponse>>> {
    let (rates, total) = state
        .service
        .list_tax_rates(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        rates,
        &pagination,
        total,
    )))
}

async fn create_tax_rate(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertTaxRateRequest>,
) -> AppResult<Json<TaxRateResponse>> {
    request.validate()?;
    let r = state
        .service
        .create_tax_rate(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(r))
}

async fn update_tax_rate(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertTaxRateRequest>,
) -> AppResult<Json<TaxRateResponse>> {
    request.validate()?;
    let r = state
        .service
        .update_tax_rate(user.tenant(), id, &request, &ctx)
        .await?;
    Ok(Json(r))
}

async fn delete_tax_rate(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state
        .service
        .delete_tax_rate(user.tenant(), id, &ctx)
        .await?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct LookupQuery {
    name: String,
}

async fn lookup_tax_rate(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Query(q): Query<LookupQuery>,
) -> AppResult<Json<TaxRateResponse>> {
    let r = state
        .service
        .lookup_tax_rate(user.tenant(), &q.name)
        .await?;
    Ok(Json(r))
}

async fn list_payment_gateways(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<PaymentGatewayConfigResponse>>> {
    let (gateways, total) = state
        .service
        .list_payment_gateways(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        gateways,
        &pagination,
        total,
    )))
}

async fn upsert_payment_gateway(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertPaymentGatewayConfigRequest>,
) -> AppResult<Json<PaymentGatewayConfigResponse>> {
    request.validate()?;
    let g = state
        .service
        .upsert_payment_gateway(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(g))
}

async fn delete_payment_gateway(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(provider): Path<String>,
) -> AppResult<()> {
    let provider = GatewayProvider::from_str(&provider).ok_or_else(|| {
        crate::utils::error::AppError::BadRequest(format!("unknown provider {provider:?}"))
    })?;
    state
        .service
        .delete_payment_gateway(user.tenant(), provider, &ctx)
        .await?;
    Ok(())
}

async fn list_payments(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(filter): Query<PaymentFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<PaymentResponse>>> {
    filter.validate()?;
    let (payments, total) = state
        .service
        .list_payments(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        payments,
        &pagination,
        total,
    )))
}

async fn create_payment(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreatePaymentRequest>,
) -> AppResult<Json<PaymentResponse>> {
    request.validate()?;
    let p = state
        .service
        .create_payment(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(p))
}

async fn delete_payment(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(payment_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .service
        .delete_payment(user.tenant(), payment_id, &ctx)
        .await?;
    Ok(())
}

async fn update_invoice(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(invoice_id): Path<Uuid>,
    Json(request): Json<UpdateInvoiceRequest>,
) -> AppResult<Json<InvoiceResponse>> {
    request.validate()?;
    let inv = state
        .service
        .update_invoice(user.tenant(), invoice_id, &request, &ctx)
        .await?;
    Ok(Json(inv))
}

async fn create_invoice(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateInvoiceRequest>,
) -> AppResult<Json<InvoiceResponse>> {
    request.validate()?;
    let inv = state
        .service
        .create_invoice(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(inv))
}

/// PMS-33 core: generate an invoice from a company's billable time
/// entries. Lower-risk than overloading `POST /invoices` (whose body is
/// a fully-specified line set): this is a distinct, additive route with
/// its own DTO, so existing invoice-create callers are untouched.
async fn create_invoice_from_time_entries(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateInvoiceFromTimeEntriesRequest>,
) -> AppResult<Json<InvoiceResponse>> {
    request.validate()?;
    let inv = state
        .service
        .create_invoice_from_time_entries(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(inv))
}

async fn get_invoice(
    State(state): State<BillingRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<InvoiceResponse>> {
    // mokosh-contact-login prompt 008: staff branch preserves the
    // pre-sweep RequireBilling+RequireFinance gate via
    // `assert_staff_billing_finance`; contact branch requires
    // invoices:read + Company scope check, 404ing a foreign row.
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => {
            assert_staff_billing_finance(auth)?;
        }
        CallerContext::Contact(_) => {
            caller.require_capability(caps::INVOICES_READ, &db).await?;
        }
    }
    let inv = state.service.get_invoice(tenant, invoice_id).await?;
    if let CallerContext::Contact(session) = &caller {
        if inv.company_id != session.company_id {
            return Err(AppError::NotFound("Invoice".to_string()));
        }
    }
    Ok(Json(inv))
}

async fn list_invoices(
    State(state): State<BillingRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Query(mut filter): Query<InvoiceFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<InvoiceResponse>>> {
    filter.validate()?;
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => {
            assert_staff_billing_finance(auth)?;
        }
        CallerContext::Contact(session) => {
            caller.require_capability(caps::INVOICES_READ, &db).await?;
            filter.company_id = Some(session.company_id);
        }
    }
    let (invoices, total) = state
        .service
        .list_invoices(tenant, &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        invoices,
        &pagination,
        total,
    )))
}

/// mokosh-contact-login prompt 008: reproduce the RequireBilling +
/// RequireFinance behaviour inline for a handler that now takes
/// `RequireCallerContext` instead of the two dedicated extractors, so
/// the staff branch still 404s a tenant with billing disabled and
/// 403s a non-finance role. Kept as a small helper because two of the
/// swept invoice handlers need it verbatim.
fn assert_staff_billing_finance(auth: &crate::modules::auth::AuthState) -> AppResult<()> {
    let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
    let role = user.role.as_str();
    if !matches!(role, "super_admin" | "admin" | "finance") {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }
    Ok(())
}
