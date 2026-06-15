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
use crate::modules::auth::{RequireContracts, RequireFinance, TenantScoped};
use crate::utils::error::AppResult;
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
    RequireContracts { user: u, .. }: RequireContracts,
    Query(f): Query<ContractFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ContractResponse>>> {
    f.validate()?;
    let (items, total) = s
        .service
        .list_contracts(u.tenant(), &f, &pagination)
        .await?;
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
    RequireContracts { user: u, .. }: RequireContracts,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ContractResponse>> {
    Ok(Json(s.service.get_contract(u.tenant(), id).await?))
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
