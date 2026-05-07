//! Authentication API routes

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    google_login, rate_limit, AuthService, ChangePasswordRequest, CreateUserRequest,
    ForgotPasswordRequest, LoginRequest, LoginResponse, RefreshTokenRequest, RefreshTokenResponse,
    ResetPasswordRequest, SessionInfo, UpdateUserRequest, UserResponse,
};
use crate::modules::auth::middleware::RequireAuth;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

/// Application state for auth routes
#[derive(Clone)]
pub struct AuthRouterState {
    pub auth_service: Arc<AuthService>,
    pub google_oauth: Arc<google_oauth_flow::Client>,
    /// Origin where the SPA is served. Used as the `postMessage` target
    /// origin in the popup-closing HTML.
    pub client_origin: String,
    /// JWT secret used to HMAC-sign the OAuth state cookie. Same key as
    /// the access/refresh token signer.
    pub jwt_secret: String,
    /// Whether to set the `Secure` flag on the OAuth state cookie.
    /// `false` over plain HTTP localhost in dev; `true` in prod.
    pub cookie_secure: bool,
}

/// Create the auth router
pub fn auth_routes(
    auth_service: AuthService,
    google_oauth: Arc<google_oauth_flow::Client>,
    client_origin: String,
    jwt_secret: String,
    cookie_secure: bool,
) -> Router {
    let state = AuthRouterState {
        auth_service: Arc::new(auth_service),
        google_oauth,
        client_origin,
        jwt_secret,
        cookie_secure,
    };

    // Per-IP rate limiter shared across `/login` requests for the
    // lifetime of the server (audit F2).
    let login_limiter = rate_limit::login_limiter();

    Router::new()
        // Public routes — `/login` is wrapped in a per-IP rate limiter
        // (5/min) to harden against credential stuffing.
        .route(
            "/login",
            post(login).layer(middleware::from_fn_with_state(
                login_limiter,
                rate_limit::login_rate_limit,
            )),
        )
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
        // Google OAuth
        .route("/google", get(google_authorize))
        .route("/google/callback", get(google_callback))
        // Protected routes
        .route("/me", get(get_current_user))
        .route("/me", put(update_current_user))
        .route("/me/password", put(change_password))
        .route("/me/sessions", get(get_sessions))
        .route("/me/sessions/{session_id}", delete(delete_session))
        // User management (admin only)
        .route("/users", get(list_users))
        .route("/users", post(create_user))
        .route("/users/{user_id}", get(get_user))
        .route("/users/{user_id}", put(update_user))
        .with_state(state)
}

/// Login endpoint
async fn login(
    State(state): State<AuthRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    request.validate()?;

    let ip_address = Some(addr.ip().to_string());
    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let response = state
        .auth_service
        .login(&request, ip_address, user_agent)
        .await?;

    Ok(Json(response))
}

/// Logout endpoint
async fn logout(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    headers: HeaderMap,
) -> AppResult<()> {
    // Extract session ID from token
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Ok(claims) = state.auth_service.decode_token(token) {
                    state.auth_service.logout(claims.sid).await?;
                }
            }
        }
    }

    Ok(())
}

/// Refresh token endpoint
async fn refresh_token(
    State(state): State<AuthRouterState>,
    Json(request): Json<RefreshTokenRequest>,
) -> AppResult<Json<RefreshTokenResponse>> {
    let response = state
        .auth_service
        .refresh_token(&request.refresh_token)
        .await?;

    Ok(Json(response))
}

/// Forgot password endpoint
async fn forgot_password(
    State(state): State<AuthRouterState>,
    Json(request): Json<ForgotPasswordRequest>,
) -> AppResult<()> {
    request.validate()?;
    state
        .auth_service
        .request_password_reset(&request.email)
        .await?;
    Ok(())
}

/// Reset password endpoint
async fn reset_password(
    State(state): State<AuthRouterState>,
    Json(request): Json<ResetPasswordRequest>,
) -> AppResult<()> {
    request.validate()?;
    state.auth_service.reset_password(&request).await?;
    Ok(())
}

/// Get current user endpoint
async fn get_current_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<UserResponse>> {
    let full_user = state.auth_service.get_user_by_id(user.id).await?;
    Ok(Json(full_user.into()))
}

/// Update current user endpoint
async fn update_current_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    request.validate()?;

    // Users can't change their own role or status
    let sanitized_request = UpdateUserRequest {
        role: None,
        status: None,
        ..request
    };

    let updated = state
        .auth_service
        .update_user(user.id, &sanitized_request)
        .await?;

    Ok(Json(updated.into()))
}

/// Change password endpoint
async fn change_password(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<ChangePasswordRequest>,
) -> AppResult<()> {
    request.validate()?;
    state
        .auth_service
        .change_password(user.id, &request)
        .await?;
    Ok(())
}

/// Get user sessions
async fn get_sessions(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    headers: HeaderMap,
) -> AppResult<Json<Vec<SessionInfo>>> {
    // Get current session ID from token
    let current_session_id = if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                state
                    .auth_service
                    .decode_token(token)
                    .map(|c| c.sid)
                    .unwrap_or(Uuid::nil())
            } else {
                Uuid::nil()
            }
        } else {
            Uuid::nil()
        }
    } else {
        Uuid::nil()
    };

    let sessions = state
        .auth_service
        .get_user_sessions(user.id, current_session_id)
        .await?;

    Ok(Json(sessions))
}

/// Delete a session
async fn delete_session(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Path(session_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .auth_service
        .delete_session(user.id, session_id)
        .await?;
    Ok(())
}

/// List users (admin only)
async fn list_users(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    axum::extract::Query(pagination): axum::extract::Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<UserResponse>>> {
    // Check admin permission
    if !user.role.is_admin() && !matches!(user.role, super::UserRole::Manager) {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    let (users, total) = state
        .auth_service
        .list_users(user.tenant_id, &pagination)
        .await?;

    Ok(Json(PaginatedResponse::new(
        users.into_iter().map(UserResponse::from).collect(),
        pagination.page,
        pagination.per_page(),
        total,
    )))
}

/// Create user (admin only)
async fn create_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<CreateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    // Check admin permission
    if !user.role.is_admin() {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    request.validate()?;

    let new_user = state
        .auth_service
        .create_user(user.tenant_id, &request)
        .await?;

    Ok(Json(new_user.into()))
}

/// Get user by ID (admin only)
async fn get_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<UserResponse>> {
    // Check admin permission or same user
    if !user.role.is_admin() && user.id != user_id {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    let target_user = state.auth_service.get_user_by_id(user_id).await?;

    Ok(Json(target_user.into()))
}

/// Update user (admin only)
async fn update_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    // Check admin permission
    if !user.role.is_admin() {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    request.validate()?;

    let updated = state.auth_service.update_user(user_id, &request).await?;

    Ok(Json(updated.into()))
}

// ---------------------------------------------------------------------------
// Google OAuth handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GoogleCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Step 1 of the OAuth flow: redirect the browser to Google's consent
/// page. Sets a short-lived signed cookie carrying the CSRF state and
/// PKCE verifier so the callback can verify them.
async fn google_authorize(State(state): State<AuthRouterState>) -> Result<Response, AppError> {
    let (url, auth_state) = state
        .google_oauth
        .build_authorize_url()
        .map_err(|e| AppError::internal(format!("OAuth setup failed: {e}")))?;

    let cookie = google_login::encode_state_cookie(
        &auth_state,
        state.jwt_secret.as_bytes(),
        state.cookie_secure,
    )
    .map_err(|e| AppError::internal(format!("OAuth state cookie failed: {e}")))?;

    let cookie_value = HeaderValue::from_str(&cookie)
        .map_err(|e| AppError::internal(format!("invalid cookie header: {e}")))?;

    let mut response = Redirect::to(url.as_str()).into_response();
    response.headers_mut().append(SET_COOKIE, cookie_value);
    Ok(response)
}

/// Step 2: Google redirects the browser back here with `?code&state`.
/// Verify the state cookie, exchange the code for userinfo, find or
/// auto-provision the user, then return an HTML page that posts the
/// JWT response to `window.opener` and closes itself.
async fn google_callback(
    State(state): State<AuthRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<GoogleCallbackQuery>,
) -> Response {
    let outcome = run_google_callback(&state, &addr, &headers, &query).await;
    let (payload, set_cookies): (serde_json::Value, Vec<String>) = match outcome {
        Ok(login_response) => (
            serde_json::json!({ "ok": true, "data": login_response }),
            vec![google_login::clear_state_cookie()],
        ),
        Err(message) => (
            serde_json::json!({ "ok": false, "error": message }),
            vec![google_login::clear_state_cookie()],
        ),
    };

    let mut response = google_login::callback_html(&payload, &state.client_origin).into_response();
    for cookie in set_cookies {
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(SET_COOKIE, v);
        }
    }
    response
}

/// Inner helper for `google_callback` that returns a flat `Result` so
/// errors can be turned into the popup-closing HTML payload uniformly.
async fn run_google_callback(
    state: &AuthRouterState,
    addr: &SocketAddr,
    headers: &HeaderMap,
    query: &GoogleCallbackQuery,
) -> Result<LoginResponse, String> {
    if let Some(err) = &query.error {
        let detail = query
            .error_description
            .clone()
            .unwrap_or_else(|| err.clone());
        return Err(format!("Google rejected the sign-in: {detail}"));
    }

    let code = query
        .code
        .as_deref()
        .ok_or_else(|| "missing `code` in callback".to_string())?;
    let received_state = query
        .state
        .as_deref()
        .ok_or_else(|| "missing `state` in callback".to_string())?;

    let cookie_header = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing state cookie".to_string())?;
    let cookie_value = google_login::read_state_cookie(cookie_header)
        .ok_or_else(|| "missing state cookie".to_string())?;
    let auth_state = google_login::decode_state_cookie(&cookie_value, state.jwt_secret.as_bytes())
        .map_err(|e| format!("invalid state cookie: {e}"))?;

    if auth_state.csrf_token != received_state {
        return Err("state mismatch (possible CSRF)".to_string());
    }

    let userinfo = state
        .google_oauth
        .exchange_code(code, &auth_state.pkce_verifier)
        .await
        .map_err(|e| format!("Google token exchange failed: {e}"))?;

    let ip = Some(addr.ip().to_string());
    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    state
        .auth_service
        .login_with_google(userinfo, ip, user_agent)
        .await
        .map_err(|e| e.to_string())
}
