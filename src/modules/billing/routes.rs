//! Billing HTTP routes. Endpoints land incrementally across PMS-33.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{delete, get, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::BillingService;
use crate::modules::auth::{RequireBilling, RequireFinance, TenantScoped};
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
        // PMS-911: the invoice as a client receives it. Rendered from the
        // issuer snapshot frozen when it was sent, so a later rebrand cannot
        // change a document somebody already holds.
        .route("/invoices/{invoice_id}/pdf", get(get_invoice_pdf))
        // PMS-955: the product catalog. A price list, not an inventory
        // system, and not a second home for labour pricing (`/rate-cards`).
        .route("/products", get(list_products).post(create_product))
        .route(
            "/products/{product_id}",
            get(get_product).put(update_product).delete(delete_product),
        )
        // PMS-954: a company's account over a period. GET, because it reads
        // and stores nothing: the statement is derived from the invoices,
        // payments, refunds and credit notes it summarises.
        .route("/statements", get(get_statement))
        // PMS-911: the same read model as a document. Rendered from CURRENT
        // branding, because PMS-954 made a statement reproducible rather than
        // immutable and there is no statement row for a snapshot to hang off.
        .route("/statements/pdf", get(get_statement_pdf))
        // PMS-953: the correction path for an issued invoice. No PUT and no
        // DELETE: a credit note is issued or voided, never edited, for the
        // reason the invoice it corrects is not.
        .route(
            "/credit-notes",
            get(list_credit_notes).post(create_credit_note),
        )
        .route("/credit-notes/{credit_note_id}", get(get_credit_note))
        .route(
            "/credit-notes/{credit_note_id}/void",
            axum::routing::post(void_credit_note),
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
        crate::utils::error::AppError::BadRequest(format!("Unknown provider {provider:?}"))
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
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<InvoiceResponse>> {
    let inv = state.service.get_invoice(user.tenant(), invoice_id).await?;
    Ok(Json(inv))
}

async fn list_invoices(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(filter): Query<InvoiceFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<InvoiceResponse>>> {
    filter.validate()?;
    let (invoices, total) = state
        .service
        .list_invoices(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        invoices,
        &pagination,
        total,
    )))
}

// ============================================================================
// PMS-953: credit notes
// ============================================================================

async fn list_credit_notes(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Query(filter): Query<CreditNoteFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<CreditNoteResponse>>> {
    filter.validate()?;
    let (notes, total) = state
        .service
        .list_credit_notes(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        notes,
        &pagination,
        total,
    )))
}

async fn get_credit_note(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Path(credit_note_id): Path<Uuid>,
) -> AppResult<Json<CreditNoteResponse>> {
    let note = state
        .service
        .get_credit_note(user.tenant(), credit_note_id)
        .await?;
    Ok(Json(note))
}

/// Finance-gated, like every other write that moves money: raising a credit
/// note reduces what a client owes.
async fn create_credit_note(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateCreditNoteRequest>,
) -> AppResult<Json<CreditNoteResponse>> {
    request.validate()?;
    let note = state
        .service
        .create_credit_note(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(note))
}

/// POST rather than DELETE: the row is not removed and the document still
/// exists. It stops counting against the invoice, and that is a state change.
async fn void_credit_note(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(credit_note_id): Path<Uuid>,
) -> AppResult<Json<CreditNoteResponse>> {
    let note = state
        .service
        .void_credit_note(user.tenant(), credit_note_id, &ctx)
        .await?;
    Ok(Json(note))
}

// ============================================================================
// PMS-954: statements
// ============================================================================

/// `GET /statements?company_id=&period_start=&period_end=`.
///
/// Not paginated, and deliberately so: a statement that dropped rows past a
/// page boundary would not reconcile, which is the one thing a statement has to
/// do. A caller who wants less asks for a shorter period.
async fn get_statement(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Query(query): Query<StatementQuery>,
) -> AppResult<Json<StatementResponse>> {
    query.validate()?;
    let statement = state.service.build_statement(user.tenant(), &query).await?;
    Ok(Json(statement))
}

/// PMS-911: `GET /invoices/{id}/pdf`.
///
/// Behind the same `RequireBilling` gate as the JSON it renders. A rendered
/// invoice is the same financial data in another format, and a new output
/// format must not become a side door around a permission (the PMS-350 lesson,
/// applied again in PMS-876 for the report export).
async fn get_invoice_pdf(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Response> {
    let tenant = user.tenant();
    let invoice = state.service.get_invoice(tenant, invoice_id).await?;
    let issuer = state.service.invoice_issuer(tenant, invoice_id).await?;
    let logo = crate::modules::billing::issuer::logo_bytes(tenant.get(), &issuer).await;
    let bytes = crate::pdf::render(&crate::modules::billing::documents::invoice(
        &invoice, &issuer, logo,
    ))?;
    Ok(pdf_response(
        bytes,
        &format!("{}.pdf", invoice.invoice_number),
    ))
}

/// PMS-911: `GET /statements/pdf`, taking the same query as `GET /statements`.
///
/// Finance-gated, unlike the JSON `GET /statements` beside it. That is not an
/// inconsistency introduced here, it is the correct half of one that already
/// exists: a statement is a company's whole financial account, and every
/// sibling that carries the same class of data (`/invoices`, `/payments`,
/// `/tax-rates`) is finance-gated. The JSON route and five others in this file
/// are not, which is a pre-existing gap of the kind PMS-350 closed elsewhere
/// and is tracked as PMS-962. Re-permissioning six existing endpoints does not
/// belong in a branding change; shipping a seventh that repeats the mistake
/// does not either.
async fn get_statement_pdf(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(query): Query<StatementQuery>,
) -> AppResult<Response> {
    query.validate()?;
    let tenant = user.tenant();
    let statement = state.service.build_statement(tenant, &query).await?;
    // Current branding, deliberately: see the module header of
    // `billing::documents` for why a statement is not snapshotted.
    let issuer = state.service.tenant_issuer(tenant).await?;
    let logo = crate::modules::billing::issuer::live_logo_bytes(tenant.get(), &issuer).await;
    let bytes = crate::pdf::render(&crate::modules::billing::documents::statement(
        &statement, &issuer, logo,
    ))?;
    Ok(pdf_response(
        bytes,
        &format!(
            "statement-{}-{}.pdf",
            statement.period_start, statement.period_end
        ),
    ))
}

/// One place that says what a PDF response looks like, so the two routes above
/// cannot drift. `attachment`, because a browser handed a PDF with no
/// disposition renders it in place under an API URL.
fn pdf_response(bytes: Vec<u8>, filename: &str) -> Response {
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/pdf".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        bytes,
    )
        .into_response()
}

// ============================================================================
// PMS-955: product catalog
// ============================================================================

async fn list_products(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Query(filter): Query<ProductFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ProductResponse>>> {
    filter.validate()?;
    let (products, total) = state
        .service
        .list_products(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        products,
        &pagination,
        total,
    )))
}

async fn get_product(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Path(product_id): Path<Uuid>,
) -> AppResult<Json<ProductResponse>> {
    Ok(Json(
        state.service.get_product(user.tenant(), product_id).await?,
    ))
}

async fn create_product(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertProductRequest>,
) -> AppResult<Json<ProductResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .service
            .create_product(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn update_product(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(product_id): Path<Uuid>,
    Json(request): Json<UpsertProductRequest>,
) -> AppResult<Json<ProductResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .service
            .update_product(user.tenant(), product_id, &request, &ctx)
            .await?,
    ))
}

/// Deleting is for a product nothing has sold. One that has is refused with a
/// 409 naming the alternative, because retiring a sold product is
/// `is_active = false`: the documents that sold it still name it.
async fn delete_product(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(product_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .service
        .delete_product(user.tenant(), product_id, &ctx)
        .await?;
    Ok(())
}
