//! Contracts HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::ContractsService;
use crate::db::Database;
use crate::modules::auth::{
    CallerContext, RequireCallerContext, RequireContracts, RequireFinance, TenantScoped,
};
use crate::modules::contact_portal::capabilities as caps;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct ContractsRouterState {
    pub service: Arc<ContractsService>,
}

pub fn contracts_routes(service: ContractsService) -> Router {
    let state = ContractsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/contracts", get(list_contracts).post(create_contract))
        .route(
            "/contracts/{id}",
            get(get_contract)
                .put(update_contract)
                .delete(delete_contract),
        )
        .route(
            "/contracts/{id}/items",
            get(list_contract_items).post(create_contract_item),
        )
        .route(
            "/contract-items/{id}",
            put(update_contract_item).delete(delete_contract_item),
        )
        .route("/contracts/{id}/hour-balance", get(get_hour_balance))
        .route("/rate-cards", get(list_rate_cards).post(create_rate_card))
        .route(
            "/rate-cards/{id}",
            get(get_rate_card)
                .put(update_rate_card)
                .delete(delete_rate_card),
        )
        .route(
            "/rate-cards/{id}/items",
            get(list_rate_card_items).post(upsert_rate_card_item),
        )
        .route(
            "/rate-card-items/{id}",
            axum::routing::delete(delete_rate_card_item),
        )
        .with_state(state)
}

async fn list_contracts(
    State(s): State<ContractsRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Query(mut f): Query<ContractFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ContractResponse>>> {
    f.validate()?;
    // PMS-935: dual-plane sweep. Staff branch keeps the pre-sweep
    // RequireContracts + RequireFinance role gate via
    // `assert_staff_contracts_finance`; contact branch loads the
    // effective `contracts:read` capability from `portal_roles` per
    // request and forces the filter's `company_id` to the session's
    // Company so a spoofed query param cannot widen visibility.
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => assert_staff_contracts_finance(auth)?,
        CallerContext::Contact(session) => {
            caller.require_capability(caps::CONTRACTS_READ, &db).await?;
            f.company_id = Some(session.company_id);
        }
    }
    let (items, total) = s.service.list_contracts(tenant, &f, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_contract(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<CreateContractRequest>,
) -> AppResult<Json<ContractResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_contract(u.tenant(), &req, &ctx).await?,
    ))
}

async fn get_contract(
    State(s): State<ContractsRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ContractResponse>> {
    // PMS-935: contact-plane callers 404 (not 403) on a foreign
    // Company's contract so a probe cannot confirm existence. Staff
    // callers keep the pre-sweep RequireContracts + RequireFinance
    // role gate via `assert_staff_contracts_finance`.
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => assert_staff_contracts_finance(auth)?,
        CallerContext::Contact(_) => {
            caller.require_capability(caps::CONTRACTS_READ, &db).await?;
        }
    }
    let contract = s.service.get_contract(tenant, id).await?;
    if let CallerContext::Contact(session) = &caller {
        if contract.company_id != session.company_id {
            return Err(AppError::NotFound("Contract".to_string()));
        }
    }
    Ok(Json(contract))
}

/// PMS-935: reproduce the RequireContracts + RequireFinance staff
/// gate inline for the dual-plane read handlers. The module gate
/// piece (RequireContracts) is intentionally dropped from the swept
/// endpoints so contact callers with `contracts:read` reach them
/// regardless of whether the tenant has the contracts module
/// toggled on for staff: portal capability is the authorization
/// signal here, not the tenant's staff-side module enablement.
fn assert_staff_contracts_finance(auth: &crate::modules::auth::AuthState) -> AppResult<()> {
    let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
    let role = user.role.as_str();
    if !matches!(role, "super_admin" | "admin" | "finance") {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }
    Ok(())
}

async fn update_contract(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateContractRequest>,
) -> AppResult<Json<ContractResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_contract(u.tenant(), id, &req, &ctx)
            .await?,
    ))
}

async fn delete_contract(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_contract(u.tenant(), id, &ctx).await
}

async fn list_contract_items(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ContractItemResponse>>> {
    let (items, total) = s
        .service
        .list_contract_items(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_contract_item(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertContractItemRequest>,
) -> AppResult<Json<ContractItemResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .create_contract_item(u.tenant(), id, &req, &ctx)
            .await?,
    ))
}

async fn update_contract_item(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertContractItemRequest>,
) -> AppResult<Json<ContractItemResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_contract_item(u.tenant(), id, &req, &ctx)
            .await?,
    ))
}

async fn delete_contract_item(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_contract_item(u.tenant(), id, &ctx).await
}

async fn get_hour_balance(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ContractHourBalanceResponse>>> {
    let (items, total) = s
        .service
        .get_hour_balance(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn list_rate_cards(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<RateCardResponse>>> {
    let (items, total) = s.service.list_rate_cards(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_rate_card(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<Json<RateCardResponse>> {
    Ok(Json(s.service.get_rate_card(u.tenant(), id).await?))
}

async fn create_rate_card(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertRateCardRequest>,
) -> AppResult<Json<RateCardResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_rate_card(u.tenant(), &req, &ctx).await?,
    ))
}

async fn update_rate_card(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertRateCardRequest>,
) -> AppResult<Json<RateCardResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_rate_card(u.tenant(), id, &req, &ctx)
            .await?,
    ))
}

async fn delete_rate_card(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_rate_card(u.tenant(), id, &ctx).await
}

async fn list_rate_card_items(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<RateCardItemResponse>>> {
    let (items, total) = s
        .service
        .list_rate_card_items(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn upsert_rate_card_item(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertRateCardItemRequest>,
) -> AppResult<Json<RateCardItemResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .upsert_rate_card_item(u.tenant(), id, &req, &ctx)
            .await?,
    ))
}

async fn delete_rate_card_item(
    State(s): State<ContractsRouterState>,
    RequireContracts { user: u, .. }: RequireContracts,
    _f: RequireFinance,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_rate_card_item(u.tenant(), id, &ctx).await
}
