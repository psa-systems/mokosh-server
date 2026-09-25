//! HTTP surface for monitored systems and status observations.
//!
//! Two audiences:
//! - `POST /rmm/status` is called by RMM agents. Signed with HMAC-SHA256
//!   over the raw body using the connection's stored secret, matching
//!   the `POST /rmm/alerts` shape so no new inbound credential exists.
//! - `GET /status/*` is internal-user-authenticated: a company's own
//!   staff looking at their own systems.

use crate::utils::json::Json;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;

use super::{
    service::IngestOutcome, BackupSuccessRateResponse, CompanyBackupStatusResponse,
    IngestStatusRequest, StatusService, SystemStatusResponse, UptimeResponse,
};
use crate::modules::auth::{RequireAuth, TenantId, TenantScoped};
use crate::modules::rmm::RmmService;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct StatusRouterState {
    pub service: Arc<StatusService>,
    /// The RMM service holds the per-connection HMAC secret used by the
    /// ingest handler. Threaded in here rather than duplicated: rotating
    /// a secret is a one-place change.
    pub rmm_service: Arc<RmmService>,
}

pub fn status_routes(service: StatusService, rmm_service: Arc<RmmService>) -> Router {
    let state = StatusRouterState {
        service: Arc::new(service),
        rmm_service,
    };
    Router::new()
        .route("/rmm/status", post(ingest_status))
        .route(
            "/status/systems/{id}/current",
            get(get_system_current_status),
        )
        .route(
            "/status/companies/{company_id}/backup",
            get(get_company_backup_status),
        )
        // Trend reports live at `/reports/status/*` so they hang off the
        // reports surface the SPA already reads for every other rollup,
        // with the aggregate logic staying next to the store it reads
        // from.
        .route(
            "/reports/status/backup-success-rate",
            get(backup_success_rate_report),
        )
        .route("/reports/status/uptime", get(uptime_report))
        .with_state(state)
}

/// The source name written into `monitored_systems.external_source`.
/// Kept as a constant here because Tactical RMM is the only source the
/// first pass ingests from; a second source (Mesh Central, NinjaOne)
/// arrives as a matching constant and a router entry, not a rewrite.
const EXTERNAL_SOURCE_TACTICAL_RMM: &str = "tactical_rmm";

/// `POST /api/v1/rmm/status`. Machine-authenticated by HMAC over the raw
/// body: a byte rewritten by any middle layer turns the signature into
/// a 401, which is why the path is in the sanitizer's `RAW_BODY_PATHS`
/// list.
async fn ingest_status(
    State(state): State<StatusRouterState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> AppResult<StatusCode> {
    let request: IngestStatusRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::Unauthorized)?;

    let signature = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    // SAFETY (PMS-139): unauthenticated machine webhook. The tenant is
    // named by the signed `X-Tenant-Id` header and authenticated by the
    // HMAC check below against that tenant's per-connection secret. A
    // wrong tenant finds no secret and 401s; `from_trusted` is the
    // named escape hatch for exactly this out-of-band scope.
    let tenant_id = headers
        .get("X-Tenant-Id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(TenantId::from_trusted)
        .ok_or(AppError::Unauthorized)?;

    let secret = state
        .rmm_service
        .connection_api_secret(tenant_id, request.rmm_connection_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::Internal("hmac key invalid".to_string()))?;
    mac.update(&body);
    let expected = mac.finalize().into_bytes();
    let expected_b64 = BASE64.encode(expected);
    if !constant_time_eq::constant_time_eq(expected_b64.as_bytes(), signature.as_bytes()) {
        return Err(AppError::Unauthorized);
    }

    match state
        .service
        .ingest(tenant_id, EXTERNAL_SOURCE_TACTICAL_RMM, &request)
        .await?
    {
        // Both outcomes answer 204 so a naive replay from Tactical RMM
        // sees the same shape whether or not this call is the one that
        // wrote the row.
        IngestOutcome::Recorded | IngestOutcome::Duplicate => Ok(StatusCode::NO_CONTENT),
    }
}

/// Latest observation per known check kind for one monitored system.
async fn get_system_current_status(
    State(state): State<StatusRouterState>,
    RequireAuth(user): RequireAuth,
    Path(system_id): Path<Uuid>,
) -> AppResult<Json<SystemStatusResponse>> {
    let response = state
        .service
        .latest_for_system(user.tenant(), system_id)
        .await?;
    Ok(Json(response))
}

/// Per-company backup rollup: every monitored system on the company and
/// the current backup outcome per system.
async fn get_company_backup_status(
    State(state): State<StatusRouterState>,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
) -> AppResult<Json<CompanyBackupStatusResponse>> {
    let response = state
        .service
        .backup_for_company(user.tenant(), company_id)
        .await?;
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
struct AggregateWindow {
    company_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
}

impl AggregateWindow {
    fn validate(&self) -> AppResult<()> {
        if self.from >= self.to {
            return Err(AppError::validation_field(
                "from",
                "from must be earlier than to",
            ));
        }
        Ok(())
    }
}

/// `GET /reports/status/backup-success-rate?company_id=..&from=..&to=..`.
/// Both `from` and `to` are RFC 3339 timestamps; the window is a
/// half-open interval `[from, to)` so a day-by-day report can advance
/// with no gap and no overlap.
async fn backup_success_rate_report(
    State(state): State<StatusRouterState>,
    RequireAuth(user): RequireAuth,
    Query(window): Query<AggregateWindow>,
) -> AppResult<Json<BackupSuccessRateResponse>> {
    window.validate()?;
    let response = state
        .service
        .backup_success_rate(user.tenant(), window.company_id, window.from, window.to)
        .await?;
    Ok(Json(response))
}

/// `GET /reports/status/uptime?company_id=..&from=..&to=..`. Same
/// window semantics as the rate above.
async fn uptime_report(
    State(state): State<StatusRouterState>,
    RequireAuth(user): RequireAuth,
    Query(window): Query<AggregateWindow>,
) -> AppResult<Json<UptimeResponse>> {
    window.validate()?;
    let response = state
        .service
        .uptime(user.tenant(), window.company_id, window.from, window.to)
        .await?;
    Ok(Json(response))
}
