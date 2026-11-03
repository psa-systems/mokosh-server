//! PMS-450: HTTP routes for email-to-ticket intake.
//!
//! parity record 2026-09-22: none of these routes has a SPA caller and none
//! is meant to. `POST /email-intake` is the external email gateway's target,
//! and `/intake-tokens` / `/email-intake-log` are admin API surfaces for
//! provisioning and troubleshooting that flow; the SPA screen is deferred.
//!
//! Two surfaces share this router:
//! * the gateway-facing `POST /email-intake` (Phase 1, public
//!   route, bearer-authenticated via `tenant_intake_tokens`);
//! * the operator-facing `/intake-tokens` admin CRUD (Phase 2,
//!   admin-only, mints and revokes the bearers above).

use std::sync::Arc;

use crate::utils::json::Json;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    routing::{get, post},
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::{
    CreateIntakeTokenRequest, CreatedIntakeTokenResponse, EmailIntakeLogResponse,
    EmailIntakeRequest, EmailIntakeResponse, IntakeTokenResponse,
};
use super::service::EmailIntakeService;
use crate::modules::auth::RequireAdminUser;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct EmailIntakeRouterState {
    pub service: Arc<EmailIntakeService>,
}

pub fn email_intake_routes(service: EmailIntakeService) -> Router {
    let state = EmailIntakeRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/email-intake", post(intake))
        // PMS-450 phase 2: admin token CRUD. The token table is
        // shared with the gateway-facing surface above; minting +
        // revoking is admin-only because a token equals "can
        // create tickets as anyone in this tenant".
        .route("/intake-tokens", get(list_tokens).post(create_token))
        .route("/intake-tokens/{id}", axum::routing::delete(revoke_token))
        // PMS-469: admin-only audit-log read. The row is written by
        // every email-intake call regardless of outcome so the admin
        // can debug "gateway sent the email, no ticket appeared".
        .route("/email-intake-log/{id}", get(get_intake_log))
        .with_state(state)
}

/// `POST /api/v1/email-intake`. Bearer authentication via
/// `tenant_intake_tokens` (NOT the normal user-bearer / cookie auth
/// middleware - the email gateway has no user identity to present).
/// The route extracts the bearer manually, hashes it, resolves the
/// owning tenant via the service, then runs the intake.
///
/// Idempotent: repeated POSTs with the same Message-Id return the
/// same ticket id with `deduplicated=true`. The mail gateway can
/// retry safely.
// SPEC-7.325: a gateway retry of an identical message_id on an already-created ticket is idempotent, returning the same ticket_id with deduplicated=true rather than erroring or creating a second ticket.
async fn intake(
    State(s): State<EmailIntakeRouterState>,
    headers: HeaderMap,
    Json(req): Json<EmailIntakeRequest>,
) -> AppResult<Json<EmailIntakeResponse>> {
    // SPEC-7.317: req.validate() runs, mapped through AppError::from, before the bearer is resolved or intake runs; an invalid payload never reaches resolve_token or intake.
    req.validate().map_err(AppError::from)?;
    // SPEC-7.318: authentication is a bearer token read directly off the request, not the normal user-session/cookie auth middleware.
    let bearer = extract_bearer(&headers)?;
    let resolved = s.service.resolve_token(&bearer).await?;
    let response = s.service.intake(resolved.tenant_id, req).await?;
    Ok(Json(response))
}

/// `GET /api/v1/intake-tokens`. Admin-only. Returns every token
/// (active + revoked) for the caller's tenant so the operator can
/// audit + revoke.
// SPEC-7.367: GET /intake-tokens requires an admin user and returns every token (active and revoked) for the caller's tenant.
// SPEC-7.377: admin-facing routes derive their TenantId via TenantId::from_trusted(u.tenant_id) from the authenticated admin user, not from any request body field.
async fn list_tokens(
    State(s): State<EmailIntakeRouterState>,
    RequireAdminUser(u): RequireAdminUser,
) -> AppResult<Json<Vec<IntakeTokenResponse>>> {
    let rows = s
        .service
        .list_tokens(crate::modules::auth::TenantId::from_trusted(u.tenant_id))
        .await?;
    Ok(Json(rows))
}

/// `POST /api/v1/intake-tokens`. Mints a fresh bearer. The
/// plaintext is on the response EXACTLY ONCE - only the SHA-256
/// hash is stored. The SPA must surface the plaintext in a copy-
/// to-clipboard modal with "this is the last time you can see
/// this" copy.
// SPEC-7.368: POST /intake-tokens requires an admin user and validates the request before calling the service.
async fn create_token(
    State(s): State<EmailIntakeRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Json(req): Json<CreateIntakeTokenRequest>,
) -> AppResult<Json<CreatedIntakeTokenResponse>> {
    req.validate().map_err(AppError::from)?;
    let resp = s
        .service
        .create_token(
            crate::modules::auth::TenantId::from_trusted(u.tenant_id),
            req,
        )
        .await?;
    Ok(Json(resp))
}

/// `DELETE /api/v1/intake-tokens/{id}`. Revokes by setting
/// `revoked_at`. Soft-delete because a hard delete would also
/// erase the audit trail the gateway depends on for "who used what
/// token and when".
// SPEC-7.372: DELETE /intake-tokens/{id} requires an admin user, scopes to the caller's tenant, and revokes idempotently.
async fn revoke_token(
    State(s): State<EmailIntakeRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    s.service
        .revoke_token(
            crate::modules::auth::TenantId::from_trusted(u.tenant_id),
            id,
        )
        .await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}

/// `GET /api/v1/email-intake-log/{id}`. Admin-only. Returns the
/// audit row for one inbound intake (raw headers + body, the
/// resulting ticket id if any, the error string if the flow failed).
// SPEC-7.366: GET /email-intake-log/{id} requires an admin user and scopes the lookup to the caller's tenant.
async fn get_intake_log(
    State(s): State<EmailIntakeRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<EmailIntakeLogResponse>> {
    let row = s
        .service
        .get_intake_log(
            crate::modules::auth::TenantId::from_trusted(u.tenant_id),
            id,
        )
        .await?;
    Ok(Json(row))
}

/// Pull `Authorization: Bearer <token>` out of the request headers
/// or 401. Reading the header here rather than at the middleware
/// layer keeps the email-intake route free of the normal user-auth
/// middleware (which would 401 because there is no `users` row to
/// resolve from a tenant_intake_token).
// SPEC-7.319: returns AppError::Unauthorized when the Authorization header is absent, is not valid header-string text, does not start with "Bearer " or "bearer " (other casings rejected), or has an empty token after stripping the prefix.
fn extract_bearer(headers: &HeaderMap) -> AppResult<String> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let trimmed = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized)?;
    if trimmed.is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok(trimmed.to_string())
}
