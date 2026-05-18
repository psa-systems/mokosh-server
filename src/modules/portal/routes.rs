//! Portal HTTP routes.
//!
//! Layout intentionally mirrors `auth/routes.rs` so a reader who knows
//! the agent surface can navigate this one. The router returned here
//! is meant to be mounted at `/api/v1/portal` and wrapped in
//! `portal_auth_middleware`.

use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use validator::Validate;

use super::middleware::{portal_auth_middleware, PortalAuthMiddleware, RequirePortalAuth};
use super::service::PortalAuthService;
use super::{CurrentContact, PortalLoginRequest, PortalLoginResponse};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct PortalRouterState {
    pub service: Arc<PortalAuthService>,
}

/// Build the `/api/v1/portal` router. Wires the portal auth middleware
/// at the outermost layer so every handler sees either a valid
/// `PortalAuthState` or the default (unauthenticated) one.
pub fn portal_routes(service: PortalAuthService) -> Router {
    let state = PortalRouterState {
        service: Arc::new(service.clone()),
    };
    let mw = PortalAuthMiddleware::new(service);

    Router::new()
        // Public: login. No auth required to call this.
        .route("/auth/login", post(login))
        // Protected: profile + the tickets/invoices/kb sub-routers
        // mounted by other commits in this story.
        .route("/auth/me", get(me))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            mw,
            portal_auth_middleware,
        ))
}

async fn login(
    State(state): State<PortalRouterState>,
    Json(request): Json<PortalLoginRequest>,
) -> AppResult<Json<PortalLoginResponse>> {
    request.validate()?;
    let resp = state.service.login(&request).await?;
    Ok(Json(resp))
}

async fn me(RequirePortalAuth(contact): RequirePortalAuth) -> AppResult<Json<CurrentContact>> {
    Ok(Json(contact))
}
