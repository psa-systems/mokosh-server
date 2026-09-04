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
        // PMS-911 / PMS-936: the invoice as a client receives it. Rendered
        // from the issuer snapshot frozen when it was sent, so a later rebrand
        // cannot change a document somebody already holds. Contact plane gates
        // on `invoices:download_pdf`; staff plane keeps the standard
        // RequireBilling + RequireFinance gates.
        .route(
            "/invoices/{invoice_id}/pdf",
            axum::routing::get(get_invoice_pdf),
        )
        // PMS-914: dual-plane "Pay Now" surface. The PMS-711 service
        // method (`create_invoice_checkout_session`) has been in
        // place since the Stripe adapter landed but the retired
        // `/portal/*` tree was the only mount site; this restores
        // the route on the dual-plane billing router. Contact plane
        // gates on `invoices:pay` (Billing-Contact role by default);
        // staff plane keeps the RequireBilling + RequireFinance
        // inline check the sibling handlers use.
        .route(
            "/invoices/{invoice_id}/pay",
            axum::routing::post(pay_invoice),
        )
        // MAPPS-666 (mokosh-invoices P1a): a read the SPA fires on
        // invoice-detail mount to decide whether the Pay Now button
        // should render, and if so with what label. Fired alongside
        // the invoice-detail fetch so the button state is decided
        // before the caller ever clicks it: a click that always
        // 400s because no gateway is configured is a worse UX than
        // a greyed button with a tooltip explaining why. Contact
        // plane gates on `invoices:read` (NOT `invoices:pay`) so a
        // Support Contact sees the same coherent empty state a
        // Billing Contact would.
        .route(
            "/invoices/{invoice_id}/payment-readiness",
            axum::routing::get(get_invoice_payment_readiness),
        )
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
        // PMS-959: the credit note as it was issued. Stored at creation, like
        // the invoice document, because a credit note is never edited.
        .route(
            "/credit-notes/{credit_note_id}/pdf",
            get(get_credit_note_pdf),
        )
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
    _finance: RequireFinance,
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
            // MAPPS-670 (mokosh-invoices P1e): the portal must never
            // see a draft. Server-side so the count meta agrees with
            // the rows (a client-side skip leaves `total` inflated
            // and pagination misleading).
            filter.exclude_draft = true;
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

// ============================================================================
// PMS-953: credit notes
// ============================================================================

async fn list_credit_notes(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
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
    _finance: RequireFinance,
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
    _finance: RequireFinance,
    Query(query): Query<StatementQuery>,
) -> AppResult<Json<StatementResponse>> {
    query.validate()?;
    let statement = state.service.build_statement(user.tenant(), &query).await?;
    Ok(Json(statement))
}

/// PMS-911 / PMS-936: dual-plane `GET /invoices/{id}/pdf`.
///
/// Contact plane gates on `invoices:download_pdf` plus a Company-scope check
/// that 404s a foreign invoice; staff plane keeps the finance inline check.
/// After the gate passes the handler renders (or serves the stored bytes) via
/// the shared PMS-959 issuer path.
async fn get_invoice_pdf(
    State(state): State<BillingRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Response> {
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => {
            assert_staff_billing_finance(auth)?;
        }
        CallerContext::Contact(_) => {
            caller
                .require_capability(caps::INVOICES_DOWNLOAD_PDF, &db)
                .await?;
        }
    }
    let invoice = state.service.get_invoice(tenant, invoice_id).await?;
    if let CallerContext::Contact(session) = &caller {
        if invoice.company_id != session.company_id {
            return Err(AppError::NotFound("Invoice".to_string()));
        }
    }
    // PMS-959: the bytes that were sent, when there are any. A live render is
    // the fallback for a draft, which has not been sent and has nothing to
    // preserve, and for an invoice sent before PMS-959, which is how those
    // documents always rendered.
    //
    // PMS-992: only a FROZEN invoice reads the store. The send writes the
    // document before it emails, and a refused email rolls the transition
    // back but not the bytes (storage is not transactional), so a draft can
    // have a stale render sitting at its key. Serving it would show an
    // operator a document that no longer matches what they are editing.
    let stored = if invoice.status.is_frozen() {
        crate::modules::billing::documents::read_issued(tenant.get(), invoice_id).await
    } else {
        None
    };
    let bytes = match stored {
        Some(stored) => stored,
        None => {
            let issuer = state.service.invoice_issuer(tenant, invoice_id).await?;
            let bill_to = state
                .service
                .bill_to(tenant, invoice.company_id, invoice.billing_contact_id)
                .await?;
            let logo = crate::modules::billing::issuer::logo_bytes(tenant.get(), &issuer).await;
            crate::pdf::render(&crate::modules::billing::documents::invoice(
                &invoice, &issuer, &bill_to, logo,
            ))?
        }
    };
    Ok(pdf_response(
        bytes,
        &format!("{}.pdf", invoice.invoice_number),
    ))
}

/// PMS-914 / PMS-711: mint a hosted checkout session for an invoice
/// balance. Contact plane gates on `invoices:pay` plus a Company-scope
/// check that 404s a foreign invoice (enumeration-resistant, matches
/// the sibling `get_invoice` + `get_invoice_pdf` pattern); staff plane
/// keeps the billing/finance inline gate. The 400s from the service
/// (invoice in a non-payable status, zero balance, no active gateway)
/// pass through unchanged.
async fn pay_invoice(
    State(state): State<BillingRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(invoice_id): Path<Uuid>,
    Json(request): Json<PayInvoiceRequest>,
) -> AppResult<Json<PayInvoiceResponse>> {
    request.validate()?;
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => {
            assert_staff_billing_finance(auth)?;
        }
        CallerContext::Contact(_) => {
            caller.require_capability(caps::INVOICES_PAY, &db).await?;
        }
    }
    if let CallerContext::Contact(session) = &caller {
        let inv = state.service.get_invoice(tenant, invoice_id).await?;
        if inv.company_id != session.company_id {
            return Err(AppError::NotFound("Invoice".to_string()));
        }
    }
    let session = state
        .service
        .create_invoice_checkout_session(
            tenant,
            invoice_id,
            &request.success_url,
            &request.cancel_url,
        )
        .await?;
    Ok(Json(PayInvoiceResponse {
        checkout_url: session.url,
    }))
}

/// MAPPS-666 (mokosh-invoices P1a): the SPA fires this once on invoice-
/// detail mount to decide whether to render the Pay Now button + with
/// what label. A click that always 400s because no gateway is
/// configured is a worse UX than a greyed button with a tooltip
/// explaining why, so surface the state up front.
///
/// Contact plane gates on `invoices:read` (NOT `invoices:pay`) - a
/// Support Contact seeing the invoice should see the same coherent
/// empty state a Billing Contact would, even though the button
/// itself is hidden on the Support view (SPA-side `use_capability`).
/// Staff plane keeps `assert_staff_billing_finance` for parity with
/// every other billing read (PMS-962 in-source guard).
async fn get_invoice_payment_readiness(
    State(state): State<BillingRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<InvoicePaymentReadinessResponse>> {
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => {
            assert_staff_billing_finance(auth)?;
        }
        CallerContext::Contact(_) => {
            caller.require_capability(caps::INVOICES_READ, &db).await?;
        }
    }
    let invoice = state.service.get_invoice(tenant, invoice_id).await?;
    if let CallerContext::Contact(session) = &caller {
        if invoice.company_id != session.company_id {
            return Err(AppError::NotFound("Invoice".to_string()));
        }
    }
    let active = state.service.active_provider_display(tenant).await?;
    let gateway_ready = active.is_some();
    let button_label = active.map(|(id, override_label)| {
        // MAPPS-671 (mokosh-invoices P2a): the admin's override wins when
        // set; otherwise fall back to a provider-derived default so a
        // tenant that never touches the field still gets a coherent
        // label. Empty-after-trim is treated as no override so a
        // whitespace-only value cannot ship a blank button.
        override_label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| match id.as_str() {
                "stripe" => "Pay with card".to_string(),
                "paypal" => "Pay with PayPal".to_string(),
                other => format!("Pay with {other}"),
            })
    });
    let invoice_payable = matches!(
        invoice.status,
        InvoiceStatus::Pending | InvoiceStatus::Sent | InvoiceStatus::PartiallyPaid
    ) && invoice.balance_due > rust_decimal::Decimal::ZERO;
    let currency = invoice.currency.as_deref().unwrap_or("USD");
    let balance_due_display = if currency.eq_ignore_ascii_case("USD") {
        format!("${:.2}", invoice.balance_due)
    } else {
        format!("{:.2} {}", invoice.balance_due, currency)
    };
    Ok(Json(InvoicePaymentReadinessResponse {
        gateway_ready,
        button_label,
        invoice_payable,
        balance_due_display,
    }))
}

/// PMS-959: `GET /credit-notes/{id}/pdf`.
///
/// Always the stored bytes in practice: a credit note is issued at creation, so
/// unlike an invoice there is no draft state and no document without one. The
/// live render covers a credit note created before PMS-959 and nothing else.
async fn get_credit_note_pdf(
    State(state): State<BillingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(credit_note_id): Path<Uuid>,
) -> AppResult<Response> {
    let tenant = user.tenant();
    let note = state
        .service
        .get_credit_note(tenant, credit_note_id)
        .await?;
    let bytes =
        match crate::modules::billing::documents::read_issued(tenant.get(), credit_note_id).await {
            Some(stored) => stored,
            None => {
                let issuer = state.service.tenant_issuer(tenant).await?;
                let credit_to = state
                    .service
                    .credit_to(tenant, note.company_id, note.invoice_id)
                    .await?;
                let logo =
                    crate::modules::billing::issuer::live_logo_bytes(tenant.get(), &issuer).await;
                crate::pdf::render(&crate::modules::billing::documents::credit_note(
                    &note, &issuer, &credit_to, logo,
                ))?
            }
        };
    Ok(pdf_response(
        bytes,
        &format!("{}.pdf", note.credit_note_number),
    ))
}

/// PMS-911: `GET /statements/pdf`, taking the same query as `GET /statements`.
///
/// Finance-gated like everything else in this file. PMS-911 gated this one and
/// left the JSON route beside it ungated, because re-permissioning six existing
/// endpoints did not belong in a branding change; PMS-962 closed that gap, so
/// the two answer a given role identically again.
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
    let account = state
        .service
        .statement_account(tenant, statement.company_id)
        .await?;
    let logo = crate::modules::billing::issuer::live_logo_bytes(tenant.get(), &issuer).await;
    let bytes = crate::pdf::render(&crate::modules::billing::documents::statement(
        &statement, &issuer, &account, logo,
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
    _finance: RequireFinance,
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
    _finance: RequireFinance,
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

#[cfg(test)]
mod finance_gate {
    /// Every handler in this file that takes the module gate takes the role
    /// gate too (PMS-962).
    ///
    /// The gap this closes was not one mistake, it was the same mistake three
    /// times: PMS-953 added `list_credit_notes` and `get_credit_note`, PMS-954
    /// added `get_statement`, and PMS-955 added `list_products` and
    /// `get_product`, each with `RequireBilling` alone. `lookup_tax_rate` had
    /// been that way since PMS-40. The effect was that a technician refused
    /// `GET /invoices` was served `GET /statements`, which carries the same
    /// invoice totals plus the whole payment history, which is the shape of
    /// defect PMS-350 exists to have closed.
    ///
    /// Review had already let it through three times, so the rule is enforced
    /// rather than remembered. It reads this file's own source, the way
    /// `storage::tests::there_is_one_default_root` does, so a new route is
    /// caught by `cargo test --lib` with no script, recipe or CI step to add.
    ///
    /// [`UNGATED`] is the deliberate-exception list and is EMPTY. Adding to it
    /// means writing down why a financial read is open to every role, which is
    /// the conversation this guard exists to force.
    const UNGATED: &[&str] = &[];

    #[test]
    fn every_billing_handler_also_takes_the_finance_gate() {
        const SRC: &str = include_str!("routes.rs");

        let mut missing: Vec<&str> = Vec::new();
        let mut seen = 0usize;
        for chunk in SRC.split("async fn ").skip(1) {
            let Some((name, rest)) = chunk.split_once('(') else {
                continue;
            };
            // The argument list, which ends at the return arrow.
            let Some((args, _)) = rest.split_once(") ->") else {
                continue;
            };
            if !args.contains("RequireBilling") {
                continue;
            }
            seen += 1;
            if !args.contains("RequireFinance") && !UNGATED.contains(&name) {
                missing.push(name);
            }
        }

        assert!(
            seen > 20,
            "the scan found only {seen} gated handlers, so it has stopped \
             matching this file's shape and is no longer proving anything"
        );
        assert!(
            missing.is_empty(),
            "these handlers read financial data behind the module gate alone: \
             {missing:?}. Add `_finance: RequireFinance`, or add the name to \
             UNGATED with a comment saying why every role may read it."
        );
    }

    /// And the exception list stays empty until somebody argues otherwise.
    ///
    /// Two candidates were considered and gated in PMS-962. `products` is a
    /// price list, and the case for opening it is a technician quoting work -
    /// but `/quotes` is itself finance-gated (PMS-672), so that technician
    /// cannot build the quote either and the exception would buy nothing.
    /// `tax-rates/lookup` returns a rate by name from the same table whose CRUD
    /// routes beside it are gated, so leaving it open would have been an
    /// oversight rather than a decision.
    #[test]
    fn the_exception_list_is_empty() {
        assert!(
            UNGATED.is_empty(),
            "an exception was added without this test being revisited: {UNGATED:?}"
        );
    }
}
