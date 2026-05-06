//! Authentication API routes

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    routing::{delete, get, post, put},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    AuthService, ChangePasswordRequest, CreateUserRequest, ForgotPasswordRequest, LoginRequest,
    LoginResponse, RefreshTokenRequest, RefreshTokenResponse, ResetPasswordRequest, SessionInfo,
    UpdateUserRequest, UserResponse,
};
use crate::modules::auth::middleware::RequireAuth;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

/// Application state for auth routes
#[derive(Clone)]
pub struct AuthRouterState {
    pub auth_service: Arc<AuthService>,
}

/// Create the auth router
pub fn auth_routes(auth_service: AuthService) -> Router {
    let state = AuthRouterState {
        auth_service: Arc::new(auth_service),
    };

    Router::new()
        // Public routes
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
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

    // TODO: Implement proper pagination query
    // For now, return empty response
    Ok(Json(PaginatedResponse::new(
        vec![],
        pagination.page,
        pagination.per_page(),
        0,
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
