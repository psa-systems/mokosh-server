//! PMS-450: HTTP routes for email-to-ticket intake.
//!
//! Two surfaces share this router:
//! * the gateway-facing `POST /email-intake` (Phase 1, public
//!   route, bearer-authenticated via `tenant_intake_tokens`);
//! * the operator-facing `/intake-tokens` admin CRUD (Phase 2,
//!   admin-only, mints and revokes the bearers above).

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::{
    CreateIntakeTokenRequest, CreatedIntakeTokenResponse, EmailIntakeRequest, EmailIntakeResponse,
    IntakeTokenResponse,
};
use super::service::EmailIntakeService;
use crate::modules::auth::{RequireAdmin, RequireAuth};
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
async fn intake(
    State(s): State<EmailIntakeRouterState>,
    headers: HeaderMap,
    Json(req): Json<EmailIntakeRequest>,
) -> AppResult<Json<EmailIntakeResponse>> {
    req.validate().map_err(AppError::from)?;
    let bearer = extract_bearer(&headers)?;
    let resolved = s.service.resolve_token(&bearer).await?;
    let response = s.service.intake(resolved.tenant_id, req).await?;
    Ok(Json(response))
}

/// `GET /api/v1/intake-tokens`. Admin-only. Returns every token
/// (active + revoked) for the caller's tenant so the operator can
/// audit + revoke.
async fn list_tokens(
    State(s): State<EmailIntakeRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
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
async fn create_token(
    State(s): State<EmailIntakeRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
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
async fn revoke_token(
    State(s): State<EmailIntakeRouterState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
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

/// Pull `Authorization: Bearer <token>` out of the request headers
/// or 401. Reading the header here rather than at the middleware
/// layer keeps the email-intake route free of the normal user-auth
/// middleware (which would 401 because there is no `users` row to
/// resolve from a tenant_intake_token).
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
