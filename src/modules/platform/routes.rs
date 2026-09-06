//! MAPPS-513: `/api/v1/platform` routes.
//!
//! - `POST /platform/login` — issue a platform-admin session.
//! - `PUT /platform/me/password` — change platform-admin password.
//!
//! `RequirePlatformAdmin` extractor reads the bearer, decodes it as a
//! `typ="platform"` JWT, resolves the admin id + email. Distinct code
//! path from the tenant `auth_middleware` — a platform bearer is
//! never treated as a tenant user (or vice versa).

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{post, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::models::{PlatformChangePasswordRequest, PlatformLoginRequest, PlatformLoginResponse};
use super::service::PlatformAdminService;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct PlatformRouterState {
    pub platform_service: Arc<PlatformAdminService>,
}

pub fn platform_routes(platform_service: PlatformAdminService) -> Router {
    let state = PlatformRouterState {
        platform_service: Arc::new(platform_service),
    };
    Router::new()
        .route("/login", post(login))
        .route("/me/password", put(change_password))
        .with_state(state)
}

async fn login(
    State(state): State<PlatformRouterState>,
    Json(request): Json<PlatformLoginRequest>,
) -> AppResult<Json<PlatformLoginResponse>> {
    request.validate()?;
    let response = state
        .platform_service
        .authenticate(&request.email, &request.password)
        .await?;
    Ok(Json(response))
}

async fn change_password(
    State(state): State<PlatformRouterState>,
    caller: RequirePlatformAdmin,
    Json(request): Json<PlatformChangePasswordRequest>,
) -> AppResult<()> {
    request.validate()?;
    state
        .platform_service
        .change_password(
            caller.id,
            &request.current_password,
            &request.new_password,
            &request.confirm_password,
        )
        .await
}

/// Extractor: require a platform-admin bearer. Reads the raw
/// `Authorization: Bearer <token>` header from the request; the
/// tenant `auth_middleware` runs earlier in the stack and won't
/// populate its own `AuthState` for a `typ="platform"` token (the
/// legacy path only accepts `typ="access"`), so a platform bearer
/// passes through untouched and lands here.
pub struct RequirePlatformAdmin {
    pub id: Uuid,
    pub email: String,
}

impl<S> axum::extract::FromRequestParts<S> for RequirePlatformAdmin
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // The platform service lives on the route's own State, but a
        // FromRequestParts extractor cannot easily reach it. Read the
        // service from the request extensions where the router
        // stashes it at build time (see `platform_routes` -> a
        // supporting `Extension` layer added in `api/router.rs`).
        let service = parts
            .extensions
            .get::<Arc<PlatformAdminService>>()
            .cloned()
            .ok_or(AppError::Unauthorized)?;
        let headers: &HeaderMap = &parts.headers;
        let token = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized)?;
        let (id, email) = service.decode_token(token)?;
        Ok(RequirePlatformAdmin { id, email })
    }
}
