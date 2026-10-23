//! MAPPS-1100 Phases A + B: HTTP surface for the Bills and Expenses
//! subsystem.
//!
//! Phase A: vendors, expense categories.
//! Phase B: bill + expense headers with lifecycle transitions.
//! Phase C (Xero / QuickBooks delegation) is blocked on MAPPS-1099.
//!
//! parity record 2026-10-23: every route this module mounts has no
//! SPA caller yet. They all land ahead of the SPA half MAPPS-1123
//! (Bills and Expenses settings + ledger surfaces) wires up. The
//! server ships first so the SPA has something concrete to call
//! against; one dated record covers both phases so a Phase C
//! follow-up has one line to update once the SPA callers merge.
//! The MAPPS-1083 recorded-exemption rule matches each path literally,
//! so every route the file mounts gets its own `//` line below.
//!
//! Phase A leaf lookups:
//! - /vendors
//! - /vendors/{id}
//! - /expense-categories
//! - /expense-categories/{id}
//!
//! Phase B headers and lifecycle transitions:
//! - /bills
//! - /bills/{id}
//! - /bills/{id}/approve
//! - /bills/{id}/void
//! - /expenses
//! - /expenses/{id}
//! - /expenses/{id}/submit
//! - /expenses/{id}/approve
//! - /expenses/{id}/reject
//! - /expenses/{id}/reimburse

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::service::{
    BillWithLines, CreateBillRequest, CreateExpenseRequest, ExpenseCategoryResponse,
    ExpenseWithLines, ExpensesService, UpsertExpenseCategoryRequest, UpsertVendorRequest,
};
use crate::modules::audit::AuditCtx;
use crate::modules::auth::{RequireBilling, RequireFinance, TenantScoped};
use crate::modules::expenses::models::{Bill, Expense, Vendor};
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
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<Bill>>> {
    pagination.reject_unsupported_sort()?;
    let (rows, total) = state.service.list_bills(user.tenant(), &pagination).await?;
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

// ── Expenses ──────────────────────────────────────────────────────────

async fn list_expenses(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<Expense>>> {
    pagination.reject_unsupported_sort()?;
    let (rows, total) = state
        .service
        .list_expenses(user.tenant(), &pagination)
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
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ExpenseWithLines>> {
    let e = state.service.get_expense(user.tenant(), id).await?;
    Ok(Json(e))
}

async fn create_expense(
    State(state): State<ExpensesRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
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
    _finance: RequireFinance,
    Path(id): Path<Uuid>,
    ctx: AuditCtx,
) -> AppResult<Json<Expense>> {
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
