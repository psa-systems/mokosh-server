//! RMM HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::RmmService;
use crate::modules::auth::{RequireAdmin, RequireRmm, TenantId, TenantScoped};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct RmmRouterState {
    pub service: Arc<RmmService>,
}

pub fn rmm_routes(service: RmmService) -> Router {
    let state = RmmRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // PMS-102 connections (+ PMS-105 second provider variant)
        .route(
            "/rmm/connections",
            get(list_connections).post(create_connection),
        )
        .route(
            "/rmm/connections/{id}",
            get(get_connection)
                .put(update_connection)
                .delete(delete_connection),
        )
        .route("/rmm/connections/{id}/test", post(test_connection))
        // PMS-103 device mappings
        .route(
            "/rmm/device-mappings",
            get(list_device_mappings).post(create_device_mapping),
        )
        .route(
            "/rmm/device-mappings/{id}",
            axum::routing::delete(delete_device_mapping),
        )
        // PMS-104 alert rules + ingest
        .route(
            "/rmm/alert-rules",
            get(list_alert_rules).post(create_alert_rule),
        )
        .route(
            "/rmm/alert-rules/{id}",
            axum::routing::delete(delete_alert_rule),
        )
        .route("/rmm/alerts", post(ingest_alert))
        .with_state(state)
}

async fn list_connections(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<RmmConnectionResponse>>> {
    let (items, total) = s.service.list_connections(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_connection(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<CreateRmmConnectionRequest>,
) -> AppResult<Json<RmmConnectionResponse>> {
    req.validate()?;
    if !matches!(
        req.provider.as_str(),
        "tactical_rmm" | "mesh_central" | "datto" | "connectwise" | "ninja_rmm"
    ) {
        return Err(AppError::BadRequest(format!(
            "provider {:?} not supported; pick tactical_rmm | mesh_central | datto | connectwise | ninja_rmm",
            req.provider
        )));
    }
    Ok(Json(
        s.service.create_connection(u.tenant(), &req, &ctx).await?,
    ))
}

async fn delete_connection(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_connection(u.tenant(), id).await
}

async fn get_connection(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<Json<RmmConnectionResponse>> {
    Ok(Json(s.service.get_connection(u.tenant(), id).await?))
}

async fn update_connection(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRmmConnectionRequest>,
) -> AppResult<Json<RmmConnectionResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_connection(u.tenant(), id, &req).await?,
    ))
}

async fn test_connection(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    Ok(Json(s.service.test_connection(u.tenant(), id).await?))
}

#[derive(serde::Deserialize)]
struct ConnQuery {
    rmm_connection_id: Option<Uuid>,
}

async fn list_device_mappings(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    Query(q): Query<ConnQuery>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<RmmDeviceMappingResponse>>> {
    let (items, total) = s
        .service
        .list_device_mappings(u.tenant(), q.rmm_connection_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_device_mapping(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<CreateRmmDeviceMappingRequest>,
) -> AppResult<Json<RmmDeviceMappingResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .create_device_mapping(u.tenant(), &req, &ctx)
            .await?,
    ))
}

async fn delete_device_mapping(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_device_mapping(u.tenant(), id).await
}

async fn list_alert_rules(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    Query(q): Query<ConnQuery>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<RmmAlertRuleResponse>>> {
    let (items, total) = s
        .service
        .list_alert_rules(u.tenant(), q.rmm_connection_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_alert_rule(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertRmmAlertRuleRequest>,
) -> AppResult<Json<RmmAlertRuleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_alert_rule(u.tenant(), &req, &ctx).await?,
    ))
}

async fn delete_alert_rule(
    State(s): State<RmmRouterState>,
    RequireRmm { user: u, .. }: RequireRmm,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_alert_rule(u.tenant(), id).await
}

/// `POST /api/v1/rmm/alerts` is callable by RMM agents (not internal
/// users); it authenticates by verifying an HMAC-SHA256 signature in
/// `X-Signature` against the connection's stored secret. This route
/// runs without `RequireAuth`.
async fn ingest_alert(
    State(s): State<RmmRouterState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> AppResult<Json<serde_json::Value>> {
    // Parse the raw bytes for field access (the connection id drives the
    // secret lookup) but keep `body` for the HMAC compare below.
    let req: IngestAlertRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::Unauthorized)?;
    req.validate()?;
    let signature = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    // SAFETY (PMS-139): this is an unauthenticated machine webhook, so there is
    // no CurrentUser to scope from. The tenant comes from the signed
    // `X-Tenant-Id` header and is authenticated below by HMAC against that
    // tenant's per-connection secret (`connection_api_secret`): a wrong tenant
    // finds no secret and 401s. `from_trusted` is the named escape hatch for
    // exactly this out-of-band scope.
    let tenant_id = headers
        .get("X-Tenant-Id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(TenantId::from_trusted)
        .ok_or(AppError::Unauthorized)?;
    let secret = s
        .service
        .connection_api_secret(tenant_id, req.rmm_connection_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    // Verify the HMAC over the ORIGINAL raw bytes (PMS-195). Re-serialising
    // the parsed JSON reorders fields, drops unknown keys, and normalises
    // whitespace, so a valid agent signature computed over the wire bytes
    // would be rejected. Compare against exactly what the agent signed.
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::Internal("hmac key invalid".to_string()))?;
    mac.update(&body);
    let expected = mac.finalize().into_bytes();
    let expected_b64 = BASE64.encode(expected);
    if !constant_time_eq::constant_time_eq(expected_b64.as_bytes(), signature.as_bytes()) {
        return Err(AppError::Unauthorized);
    }

    let created = s.service.ingest_alert(tenant_id, &req).await?;
    Ok(Json(serde_json::json!({"tickets_created": created})))
}
