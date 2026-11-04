//! HTTP surface for the Bills and Expenses subsystem (MAPPS-1100 Phases
//! A and B, delegation in MAPPS-1155).
//!
//! Phase A: vendors, expense categories. Phase B: the bill and expense
//! headers with their lifecycle transitions. MAPPS-1155 added the push to
//! Xero or QuickBooks inside `create_bill`, which changes no route here.
//!
//! # Who may do what with a claim (PMS-1535)
//!
//! Everything about vendors, categories and bills is finance's: those are
//! the MSP's own books. A CLAIM is not. `expenses.user_id` is the person
//! who spent the money and `approver_id` is whoever decided, a distinction
//! with no purpose if only the people who approve can file. So:
//!
//! - any member of the tenant can create a claim, and the submitter is the
//!   caller;
//! - a non-finance caller sees their own claims and no others, on the list
//!   and on the read;
//! - submitting is the submitter's own act, and the one transition they
//!   may make;
//! - approve, reject and reimburse stay finance's.
//!
//! `RequireBilling` stays on all of them: claims live under the billing
//! module, and a deployment with billing switched off should not grow an
//! expense surface.
//!
//! The vendor, expense-category and bill routes are called by
//! `/settings/vendors`, `/settings/expense-categories` and `/bills` in
//! mokosh-apps (MAPPS-1157), so the record that exempted them is gone.
//!
//! The claim routes are called by `/expenses` in mokosh-apps
//! (MAPPS-1163), so the record that exempted them is gone with them.
//!
//! The payment routes are called by `/bills/{id}` in mokosh-apps
//! (MAPPS-1166), so the last record in this file is gone too: every route
//! it mounts now has a caller, and `check-route-consumers` checks them
//! all again.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::service::{
    BillWithLines, BillWithPayments, CreateBillRequest, CreateExpenseRequest,
    ExpenseCategoryResponse, ExpenseWithLines, ExpensesService, RecordBillPaymentRequest,
    UpsertExpenseCategoryRequest, UpsertVendorRequest,
};
use crate::modules::audit::AuditCtx;
use crate::modules::auth::{CurrentUser, RequireBilling, RequireFinance, TenantScoped};
use crate::modules::expenses::models::{
    Bill, BillFilter, BillPayment, Expense, ExpenseFilter, Vendor,
};
use crate::utils::error::AppResult;
use crate::utils::json::Json;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct ExpensesRouterState {
    pub service: Arc<ExpensesService>,
}

/// Build the expenses router. URLs are absolute (`/vendors`,
/// `/expense-categories`) so the call site `merge`s rather than `nest`s,
/// matching the billing router shape.
pub fn expenses_routes(service: ExpensesService) -> Router {
    let state = ExpensesRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/vendors", get(list_vendors).post(create_vendor))
        .route(
            "/vendors/{id}",
            get(get_vendor).put(update_vendor).delete(delete_vendor),
        )
        .route(
            "/expense-categories",
            get(list_expense_categories).post(create_expense_category),
        )
        .route(
            "/expense-categories/{id}",
            axum::routing::put(update_expense_category),
        )
        // ── Bills ───────────────────────────────────────────────────
        .route("/bills", get(list_bills).post(create_bill))
        .route("/bills/{id}", get(get_bill))
        .route("/bills/{id}/approve", post(approve_bill))
        .route("/bills/{id}/void", post(void_bill))
        // PMS-1536: what the MSP has actually paid. `paid` is reached
        // through here and nowhere else.
        .route(
            "/bills/{id}/payments",
            get(list_bill_payments).post(record_bill_payment),
        )
        // ── Expenses ────────────────────────────────────────────────
        .route("/expenses", get(list_expenses).post(create_expense))
        .route("/expenses/{id}", get(get_expense))
        .route("/expenses/{id}/submit", post(submit_expense))
        .route("/expenses/{id}/approve", post(approve_expense))
        .route("/expenses/{id}/reject", post(reject_expense))
        .route("/expenses/{id}/reimburse", post(reimburse_expense))
        .with_state(state)
}

// ── Vendors ───────────────────────────────────────────────────────────

async fn list_vendors(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<Vendor>>> {
    pagination.reject_unsupported_sort()?;
    let (rows, total) = state
        .service
        .list_vendors(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        rows,
        &pagination,
        total,
    )))
}

async fn get_vendor(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vendor>> {
    let v = state.service.get_vendor(user.tenant(), id).await?;
    Ok(Json(v))
}

async fn create_vendor(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: AuditCtx,
    Json(request): Json<UpsertVendorRequest>,
) -> AppResult<Json<Vendor>> {
    request.validate()?;
    let v = state
        .service
        .create_vendor(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(v))
}

async fn update_vendor(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
    Json(request): Json<UpsertVendorRequest>,
) -> AppResult<Json<Vendor>> {
    request.validate()?;
    let v = state
        .service
        .update_vendor(user.tenant(), id, &request, &ctx)
        .await?;
    Ok(Json(v))
}

async fn delete_vendor(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
) -> AppResult<()> {
    state.service.delete_vendor(user.tenant(), id, &ctx).await?;
    Ok(())
}

// ── Expense categories ────────────────────────────────────────────────

async fn list_expense_categories(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ExpenseCategoryResponse>>> {
    pagination.reject_unsupported_sort()?;
    let (rows, total) = state
        .service
        .list_expense_categories(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        rows,
        &pagination,
        total,
    )))
}

async fn create_expense_category(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: AuditCtx,
    Json(request): Json<UpsertExpenseCategoryRequest>,
) -> AppResult<Json<ExpenseCategoryResponse>> {
    request.validate()?;
    let c = state
        .service
        .create_expense_category(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(c))
}

async fn update_expense_category(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
    Json(request): Json<UpsertExpenseCategoryRequest>,
) -> AppResult<Json<ExpenseCategoryResponse>> {
    request.validate()?;
    let c = state
        .service
        .update_expense_category(user.tenant(), id, &request, &ctx)
        .await?;
    Ok(Json(c))
}

// ── Bills ─────────────────────────────────────────────────────────────

async fn list_bills(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(filter): Query<BillFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<Bill>>> {
    pagination.reject_unsupported_sort()?;
    filter.validate()?;
    let (rows, total) = state
        .service
        .list_bills(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        rows,
        &pagination,
        total,
    )))
}

async fn get_bill(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<Json<BillWithLines>> {
    let b = state.service.get_bill(user.tenant(), id).await?;
    Ok(Json(b))
}

async fn create_bill(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    ctx: AuditCtx,
    Json(request): Json<CreateBillRequest>,
) -> AppResult<Json<BillWithLines>> {
    request.validate()?;
    let b = state
        .service
        .create_bill(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(b))
}

async fn approve_bill(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
) -> AppResult<Json<Bill>> {
    let b = state.service.approve_bill(user.tenant(), id, &ctx).await?;
    Ok(Json(b))
}

async fn void_bill(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
) -> AppResult<Json<Bill>> {
    let b = state.service.void_bill(user.tenant(), id, &ctx).await?;
    Ok(Json(b))
}

async fn record_bill_payment(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
    Json(request): Json<RecordBillPaymentRequest>,
) -> AppResult<Json<BillWithPayments>> {
    request.validate()?;
    // PMS-1545: the operator-facing method, which pushes to the provider
    // when one holds the bill. The inner `record_bill_payment` is what the
    // webhook receiver calls, so a payment that arrived FROM a provider is
    // never pushed back to it.
    let b = state
        .service
        .pay_bill(user.tenant(), id, &request, &ctx)
        .await?;
    Ok(Json(b))
}

async fn list_bill_payments(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<BillPayment>>> {
    let rows = state.service.list_bill_payments(user.tenant(), id).await?;
    Ok(Json(rows))
}

// ── Expenses ──────────────────────────────────────────────────────────

/// Whose claims this caller may see: `None` for every claim in the tenant,
/// `Some(their own id)` for everybody else (PMS-1535).
///
/// `can_manage_billing()` and not `is_admin()`: finance is exactly who
/// decides claims, and finance is not an admin.
fn own_claims_only(user: &CurrentUser) -> Option<Uuid> {
    if user.role.can_manage_billing() {
        None
    } else {
        Some(user.id)
    }
}

/// Refuse a claim that is somebody else's, unless this caller may see
/// every claim (PMS-1535).
fn assert_may_read(user: &CurrentUser, submitter: Uuid) -> AppResult<()> {
    if user.role.can_manage_billing() || submitter == user.id {
        Ok(())
    } else {
        Err(crate::utils::error::AppError::Forbidden(
            "That expense claim belongs to somebody else".to_string(),
        ))
    }
}

async fn list_expenses(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Query(filter): Query<ExpenseFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<Expense>>> {
    pagination.reject_unsupported_sort()?;
    filter.validate()?;
    // PMS-1535: a claim belongs to the person who made it. Finance sees
    // every claim because deciding them is their job; everybody else sees
    // their own, and the filter is forced here rather than offered as a
    // query parameter, because a scope a caller can set is a scope a
    // caller can widen.
    let (rows, total) = state
        .service
        .list_expenses(user.tenant(), own_claims_only(&user), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        rows,
        &pagination,
        total,
    )))
}

async fn get_expense(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ExpenseWithLines>> {
    let e = state.service.get_expense(user.tenant(), id).await?;
    // The 404 for an unknown id comes first, from the read above: whether
    // this claim exists is not a fact worth withholding from somebody who
    // is already in the tenant, and answering 403 before the lookup would
    // say "it exists" about an id nobody has.
    assert_may_read(&user, e.expense.user_id)?;
    Ok(Json(e))
}

async fn create_expense(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    ctx: AuditCtx,
    Json(request): Json<CreateExpenseRequest>,
) -> AppResult<Json<ExpenseWithLines>> {
    request.validate()?;
    // The submitter is the caller: an expense is per-user by schema.
    let e = state
        .service
        .create_expense(user.tenant(), user.id, &request, &ctx)
        .await?;
    Ok(Json(e))
}

async fn submit_expense(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
) -> AppResult<Json<Expense>> {
    // Submitting is the submitter's own act, so it is the one transition a
    // non-finance caller may make, and only on their own claim. Finance can
    // do it too: somebody has to be able to send on the claim of a person
    // who has left.
    let existing = state.service.get_expense(user.tenant(), id).await?;
    assert_may_read(&user, existing.expense.user_id)?;
    let e = state
        .service
        .submit_expense(user.tenant(), id, &ctx)
        .await?;
    Ok(Json(e))
}

async fn approve_expense(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
) -> AppResult<Json<Expense>> {
    let e = state
        .service
        .approve_expense(user.tenant(), id, user.id, &ctx)
        .await?;
    Ok(Json(e))
}

async fn reject_expense(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
) -> AppResult<Json<Expense>> {
    let e = state
        .service
        .reject_expense(user.tenant(), id, &ctx)
        .await?;
    Ok(Json(e))
}

async fn reimburse_expense(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
) -> AppResult<Json<Expense>> {
    let e = state
        .service
        .reimburse_expense(user.tenant(), id, &ctx)
        .await?;
    Ok(Json(e))
}
