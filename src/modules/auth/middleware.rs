//! Authentication middleware for Axum

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use super::{AuthService, AuthState, CurrentUser, JwtClaims, UserRole};
use crate::utils::error::AppError;

/// Extension to hold the current auth state
#[derive(Clone)]
pub struct AuthMiddleware {
    pub auth_service: Arc<AuthService>,
}

impl AuthMiddleware {
    pub fn new(auth_service: AuthService) -> Self {
        Self {
            auth_service: Arc::new(auth_service),
        }
    }
}

/// Extract auth state from request
pub async fn auth_middleware(
    State(auth_middleware): State<AuthMiddleware>,
    mut request: Request,
    next: Next,
) -> Response {
    // Try to extract token from Authorization header
    let auth_state = if let Some(auth_header) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                match auth_middleware.auth_service.decode_token(token) {
                    Ok(claims) => {
                        // Fetch user to get current info
                        match auth_middleware
                            .auth_service
                            .get_user_by_id(claims.sub)
                            .await
                        {
                            Ok(user) => {
                                AuthState::authenticated(user.to_current_user(), claims.tid)
                            }
                            Err(_) => AuthState::default(),
                        }
                    }
                    Err(_) => AuthState::default(),
                }
            } else {
                AuthState::default()
            }
        } else {
            AuthState::default()
        }
    } else {
        AuthState::default()
    };

    // Insert auth state into request extensions
    request.extensions_mut().insert(auth_state);

    next.run(request).await
}

/// Middleware that requires authentication
pub async fn require_auth(request: Request, next: Next) -> Result<Response, (StatusCode, String)> {
    let auth_state = request
        .extensions()
        .get::<AuthState>()
        .cloned()
        .unwrap_or_default();

    if !auth_state.is_authenticated {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authentication required".to_string(),
        ));
    }

    Ok(next.run(request).await)
}

/// Extractor for requiring authentication
#[derive(Clone)]
pub struct RequireAuth(pub CurrentUser);

impl<S> axum::extract::FromRequestParts<S> for RequireAuth
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .cloned()
            .unwrap_or_default();

        match auth_state.user {
            Some(user) => Ok(RequireAuth(user)),
            None => Err(AppError::Unauthorized),
        }
    }
}

/// Trait for role-based authorization requirements
pub trait RoleRequirement {
    fn allowed_roles() -> &'static [&'static str];
}

/// Extractor for requiring a specific role
#[derive(Clone)]
pub struct RequireRole<R: RoleRequirement>(pub CurrentUser, std::marker::PhantomData<R>);

impl<S, R> axum::extract::FromRequestParts<S> for RequireRole<R>
where
    S: Send + Sync,
    R: RoleRequirement,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .cloned()
            .unwrap_or_default();

        match auth_state.user {
            Some(user) => {
                let user_role = user.role.as_str();
                if R::allowed_roles().contains(&user_role) {
                    Ok(RequireRole(user, std::marker::PhantomData))
                } else {
                    Err(AppError::Forbidden("Insufficient permissions".to_string()))
                }
            }
            None => Err(AppError::Unauthorized),
        }
    }
}

/// Admin role requirement
pub struct AdminRoles;
impl RoleRequirement for AdminRoles {
    fn allowed_roles() -> &'static [&'static str] {
        &["super_admin", "admin"]
    }
}

/// Manager role requirement
pub struct ManagerRoles;
impl RoleRequirement for ManagerRoles {
    fn allowed_roles() -> &'static [&'static str] {
        &["super_admin", "admin", "manager"]
    }
}

/// Finance role requirement
pub struct FinanceRoles;
impl RoleRequirement for FinanceRoles {
    fn allowed_roles() -> &'static [&'static str] {
        &["super_admin", "admin", "finance"]
    }
}

/// Helper type aliases for common role requirements
pub type RequireAdmin = RequireRole<AdminRoles>;
pub type RequireManager = RequireRole<ManagerRoles>;
pub type RequireFinance = RequireRole<FinanceRoles>;

/// Get the current user's tenant ID from the request
pub fn get_tenant_id(request: &Request) -> Option<uuid::Uuid> {
    request
        .extensions()
        .get::<AuthState>()
        .and_then(|state| state.tenant_id)
}

/// Get the current user from the request
pub fn get_current_user(request: &Request) -> Option<CurrentUser> {
    request
        .extensions()
        .get::<AuthState>()
        .and_then(|state| state.user.clone())
}
