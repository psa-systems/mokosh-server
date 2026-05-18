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
use crate::modules::auth::{RequireAuth, RequireFinance};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct ContractsRouterState {
    pub service: Arc<ContractsService>,
}

pub fn contracts_routes(service: ContractsService) -> Router {
    let state = ContractsRouterState { service: Arc::new(service) };
    Router::new()
        .route("/contracts", get(list_contracts).post(create_contract))
        .route("/contracts/{id}", get(get_contract).put(update_contract).delete(delete_contract))
        .route("/contracts/{id}/items", get(list_contract_items).post(create_contract_item))
        .route("/contract-items/{id}", put(update_contract_item).delete(delete_contract_item))
        .route("/contracts/{id}/hour-balance", get(get_hour_balance))
        .route("/rate-cards", get(list_rate_cards).post(create_rate_card))
        .route("/rate-cards/{id}", put(update_rate_card).delete(delete_rate_card))
        .route("/rate-cards/{id}/items", get(list_rate_card_items).post(upsert_rate_card_item))
        .route("/rate-card-items/{id}", axum::routing::delete(delete_rate_card_item))
        .with_state(state)
}

async fn list_contracts(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth,
    Query(f): Query<ContractFilter>,
) -> AppResult<Json<Vec<ContractResponse>>> {
    f.validate()?;
    Ok(Json(s.service.list_contracts(u.tenant_id, &f).await?))
}

async fn create_contract(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Json(req): Json<CreateContractRequest>,
) -> AppResult<Json<ContractResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_contract(u.tenant_id, &req).await?))
}

async fn get_contract(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, Path(id): Path<Uuid>,
) -> AppResult<Json<ContractResponse>> {
    Ok(Json(s.service.get_contract(u.tenant_id, id).await?))
}

async fn update_contract(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>, Json(req): Json<UpdateContractRequest>,
) -> AppResult<Json<ContractResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_contract(u.tenant_id, id, &req).await?))
}

async fn delete_contract(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_contract(u.tenant_id, id).await }

async fn list_contract_items(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<ContractItemResponse>>> {
    Ok(Json(s.service.list_contract_items(u.tenant_id, id).await?))
}

async fn create_contract_item(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>, Json(req): Json<UpsertContractItemRequest>,
) -> AppResult<Json<ContractItemResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_contract_item(u.tenant_id, id, &req).await?))
}

async fn update_contract_item(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>, Json(req): Json<UpsertContractItemRequest>,
) -> AppResult<Json<ContractItemResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_contract_item(u.tenant_id, id, &req).await?))
}

async fn delete_contract_item(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_contract_item(u.tenant_id, id).await }

async fn get_hour_balance(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<ContractHourBalanceResponse>>> {
    Ok(Json(s.service.get_hour_balance(u.tenant_id, id).await?))
}

async fn list_rate_cards(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<RateCardResponse>>> {
    Ok(Json(s.service.list_rate_cards(u.tenant_id).await?))
}

async fn create_rate_card(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Json(req): Json<UpsertRateCardRequest>,
) -> AppResult<Json<RateCardResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_rate_card(u.tenant_id, &req).await?))
}

async fn update_rate_card(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>, Json(req): Json<UpsertRateCardRequest>,
) -> AppResult<Json<RateCardResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_rate_card(u.tenant_id, id, &req).await?))
}

async fn delete_rate_card(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_rate_card(u.tenant_id, id).await }

async fn list_rate_card_items(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<RateCardItemResponse>>> {
    Ok(Json(s.service.list_rate_card_items(u.tenant_id, id).await?))
}

async fn upsert_rate_card_item(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>, Json(req): Json<UpsertRateCardItemRequest>,
) -> AppResult<Json<RateCardItemResponse>> {
    req.validate()?;
    Ok(Json(s.service.upsert_rate_card_item(u.tenant_id, id, &req).await?))
}

async fn delete_rate_card_item(
    State(s): State<ContractsRouterState>, RequireAuth(u): RequireAuth, _f: RequireFinance,
    Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_rate_card_item(u.tenant_id, id).await }
