//! mokosh-contact-login prompt 004: `/api/v1/contact/*` route family.
//!
//! Public routes (login, refresh, logout, set-password, forgot-password,
//! reset-password, host hint) sit outside the auth check; the middleware
//! still runs (it decodes the token when present) but downstream
//! extractors don't. `/auth/me` is behind `RequireContactAuth`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use validator::Validate;

use super::middleware::{portal_contact_middleware, ContactAuthMiddleware, RequireContactAuth};
use super::models::*;
use super::service::ContactAuthService;
use crate::utils::error::{AppError, AppResult};

const REFRESH_COOKIE_NAME: &str = "mokosh:contact_token";
const REFRESH_COOKIE_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60; // 30 days

#[derive(Clone)]
pub struct ContactRouterState {
    pub service: Arc<ContactAuthService>,
}

/// Build the `/api/v1/contact/*` sub-router. Layered with
/// `portal_contact_middleware` so every request through this tree
/// decodes the Bearer / cookie into a `ContactAuthState` extension
/// (default when absent); downstream extractors then 401 as needed.
pub fn contact_routes(service: ContactAuthService) -> Router {
    let service_arc = Arc::new(service);
    let mw = ContactAuthMiddleware {
        service: service_arc.clone(),
    };
    let state = ContactRouterState {
        service: service_arc,
    };
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/set-password", post(set_password))
        .route("/auth/reset-password", post(reset_password))
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/me", get(me))
        .route("/portal/{slug}/host", get(portal_host))
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            mw,
            portal_contact_middleware,
        ))
}

// ============================================================================
// HANDLERS
// ============================================================================

async fn login(
    State(state): State<ContactRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ContactLoginRequest>,
) -> Result<Response, AppError> {
    request.validate()?;
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let resp = state
        .service
        .login(
            &request.slug,
            &request.email,
            &request.password,
            request.mfa_code.as_deref(),
            ua.as_deref(),
            Some(addr.ip()),
        )
        .await?;
    Ok(with_refresh_cookie(
        &resp,
        Json(resp.clone()).into_response(),
    ))
}

async fn refresh(
    State(state): State<ContactRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ContactRefreshRequest>,
) -> Result<Response, AppError> {
    request.validate()?;
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let resp = state
        .service
        .refresh(&request.refresh_token, ua.as_deref(), Some(addr.ip()))
        .await?;
    Ok(with_refresh_cookie(
        &resp,
        Json(resp.clone()).into_response(),
    ))
}

async fn logout(
    State(state): State<ContactRouterState>,
    Json(request): Json<ContactLogoutRequest>,
) -> Result<Response, AppError> {
    request.validate()?;
    state.service.logout(&request.refresh_token).await?;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    add_cookie(resp.headers_mut(), &clear_refresh_cookie());
    Ok(resp)
}

async fn set_password(
    State(state): State<ContactRouterState>,
    Json(request): Json<ContactSetPasswordRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    state
        .service
        .setup_password(&request.token, &request.password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reset_password(
    State(state): State<ContactRouterState>,
    Json(request): Json<ContactResetPasswordRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    state
        .service
        .reset_password(&request.token, &request.password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn forgot_password(
    State(state): State<ContactRouterState>,
    Json(request): Json<ContactForgotPasswordRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    state
        .service
        .request_password_reset(&request.slug, &request.email)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(
    State(state): State<ContactRouterState>,
    RequireContactAuth(session): RequireContactAuth,
) -> AppResult<Json<ContactMe>> {
    let me = state.service.me(session.tenant_id, session.id).await?;
    Ok(Json(me))
}

async fn portal_host(
    State(state): State<ContactRouterState>,
    Path(slug): Path<String>,
) -> AppResult<Json<ContactPortalHostHint>> {
    let hint = state
        .service
        .resolve_host(&slug)
        .await?
        .ok_or_else(|| AppError::not_found("portal host"))?;
    Ok(Json(hint))
}

// ============================================================================
// COOKIE HELPERS
// ============================================================================

/// mokosh-contact-login prompt 004: attach a `mokosh:contact_token`
/// cookie carrying the refresh token to a login / refresh response,
/// so the SPA can survive a hard-refresh cold-load (learns from
/// MAPPS-564 pain).
///
/// HttpOnly = JS cannot read it (XSS-resistant). Secure = TLS-only
/// (dev over http will still function because most browsers relax
/// Secure on localhost; production always has TLS). SameSite=Lax =
/// cross-site GET/POST cannot forge it. Path scoped so the cookie
/// only travels on `/api/v1/contact/auth/*` where the refresh
/// endpoint lives.
fn with_refresh_cookie(resp: &ContactLoginResponse, mut into: Response) -> Response {
    add_cookie(
        into.headers_mut(),
        &build_refresh_cookie(&resp.refresh_token),
    );
    into
}

fn build_refresh_cookie(refresh_token: &str) -> String {
    format!(
        "{name}={value}; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/contact/auth; Max-Age={max_age}",
        name = REFRESH_COOKIE_NAME,
        value = refresh_token,
        max_age = REFRESH_COOKIE_MAX_AGE_SECS,
    )
}

fn clear_refresh_cookie() -> String {
    format!(
        "{name}=; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/contact/auth; Max-Age=0",
        name = REFRESH_COOKIE_NAME,
    )
}

fn add_cookie(headers: &mut HeaderMap, cookie: &str) {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        headers.append(header::SET_COOKIE, v);
    }
}
