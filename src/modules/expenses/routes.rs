//! MAPPS-1100 Phase A: HTTP surface for the Bills and Expenses leaf
//! lookups (vendors, expense categories).
//!
//! The bills and expenses headers land in a follow-up PR with their
//! own routes; see [`crate::modules::expenses`] for the staging plan.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::service::{
    ExpenseCategoryResponse, ExpensesService, UpsertExpenseCategoryRequest, UpsertVendorRequest,
};
use crate::modules::audit::AuditCtx;
use crate::modules::auth::{RequireBilling, RequireFinance, TenantScoped};
use crate::modules::expenses::models::Vendor;
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
