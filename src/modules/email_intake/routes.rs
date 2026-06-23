//! PMS-450: HTTP route for email-to-ticket intake.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap},
    routing::post,
    Json, Router,
};
use validator::Validate;

use super::models::{EmailIntakeRequest, EmailIntakeResponse};
use super::service::EmailIntakeService;
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
