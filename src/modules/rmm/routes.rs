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
use crate::modules::auth::{RequireAdmin, RequireAuth};
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct RmmRouterState {
    pub service: Arc<RmmService>,
}

pub fn rmm_routes(service: RmmService) -> Router {
    let state = RmmRouterState { service: Arc::new(service) };
    Router::new()
        // PMS-102 connections (+ PMS-105 second provider variant)
        .route("/rmm/connections", get(list_connections).post(create_connection))
        .route("/rmm/connections/{id}", axum::routing::delete(delete_connection))
        .route("/rmm/connections/{id}/test", post(test_connection))
        // PMS-103 device mappings
        .route("/rmm/device-mappings", get(list_device_mappings).post(create_device_mapping))
        .route("/rmm/device-mappings/{id}", axum::routing::delete(delete_device_mapping))
        // PMS-104 alert rules + ingest
        .route("/rmm/alert-rules", get(list_alert_rules).post(create_alert_rule))
        .route("/rmm/alert-rules/{id}", axum::routing::delete(delete_alert_rule))
        .route("/rmm/alerts", post(ingest_alert))
        .with_state(state)
}

async fn list_connections(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
) -> AppResult<Json<Vec<RmmConnectionResponse>>> {
    Ok(Json(s.service.list_connections(u.tenant_id).await?))
}

async fn create_connection(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
    Json(req): Json<CreateRmmConnectionRequest>,
) -> AppResult<Json<RmmConnectionResponse>> {
    req.validate()?;
    if !matches!(
        req.provider.as_str(),
        "tactical_rmm" | "datto" | "connectwise" | "ninja_rmm"
    ) {
        return Err(AppError::BadRequest(format!(
            "provider {:?} not supported; pick tactical_rmm | datto | connectwise | ninja_rmm",
            req.provider
        )));
    }
    Ok(Json(s.service.create_connection(u.tenant_id, &req).await?))
}

async fn delete_connection(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_connection(u.tenant_id, id).await }

async fn test_connection(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    Ok(Json(s.service.test_connection(u.tenant_id, id).await?))
}

#[derive(serde::Deserialize)]
struct ConnQuery { rmm_connection_id: Option<Uuid> }

async fn list_device_mappings(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth,
    Query(q): Query<ConnQuery>,
) -> AppResult<Json<Vec<RmmDeviceMappingResponse>>> {
    Ok(Json(s.service.list_device_mappings(u.tenant_id, q.rmm_connection_id).await?))
}

async fn create_device_mapping(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
    Json(req): Json<CreateRmmDeviceMappingRequest>,
) -> AppResult<Json<RmmDeviceMappingResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_device_mapping(u.tenant_id, &req).await?))
}

async fn delete_device_mapping(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_device_mapping(u.tenant_id, id).await }

async fn list_alert_rules(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth,
    Query(q): Query<ConnQuery>,
) -> AppResult<Json<Vec<RmmAlertRuleResponse>>> {
    Ok(Json(s.service.list_alert_rules(u.tenant_id, q.rmm_connection_id).await?))
}

async fn create_alert_rule(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
    Json(req): Json<UpsertRmmAlertRuleRequest>,
) -> AppResult<Json<RmmAlertRuleResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_alert_rule(u.tenant_id, &req).await?))
}

async fn delete_alert_rule(
    State(s): State<RmmRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_alert_rule(u.tenant_id, id).await }

/// `POST /api/v1/rmm/alerts` is callable by RMM agents (not internal
/// users); it authenticates by verifying an HMAC-SHA256 signature in
/// `X-Signature` against the connection's stored secret. This route
/// runs without `RequireAuth`.
async fn ingest_alert(
    State(s): State<RmmRouterState>,
    headers: HeaderMap,
    Json(req): Json<IngestAlertRequest>,
) -> AppResult<Json<serde_json::Value>> {
    req.validate()?;
    let signature = headers.get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized)?;

    // The body is parsed twice (axum + our HMAC compare) to avoid a
    // raw-body extractor; we re-serialise the parsed Json for HMAC.
    let body = serde_json::to_vec(&req).map_err(|_| AppError::Unauthorized)?;
    let tenant_id = headers.get("X-Tenant-Id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Unauthorized)?;
    let secret = s.service.connection_api_secret(tenant_id, req.rmm_connection_id).await?
        .ok_or_else(|| AppError::Unauthorized)?;
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
