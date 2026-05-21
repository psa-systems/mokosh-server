//! Authentication middleware for Axum

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use super::at_jwt::{current_user_from_at_jwt, AtJwtVerifier};
use super::{AuthService, AuthState, CurrentUser};
use crate::utils::error::AppError;

/// Extension to hold the current auth state
#[derive(Clone)]
pub struct AuthMiddleware {
    pub auth_service: Arc<AuthService>,
    /// Optional `at+jwt` verifier. When set, the middleware tries
    /// EdDSA verification against `mokosh-auth`'s key set first and
    /// only falls back to the legacy HS256 path when the token is not
    /// recognisable as an `at+jwt`. This is how PSA endpoints accept
    /// access tokens minted by SSO during the transition window.
    pub at_jwt: Option<AtJwtVerifier>,
}

impl AuthMiddleware {
    pub fn new(auth_service: AuthService) -> Self {
        Self {
            auth_service: Arc::new(auth_service),
            at_jwt: None,
        }
    }

    /// Attach an `at+jwt` verifier. Call this once at startup with the
    /// `OidcKeySet` returned from `mokosh_auth::bootstrap`.
    pub fn with_at_jwt(mut self, verifier: AtJwtVerifier) -> Self {
        self.at_jwt = Some(verifier);
        self
    }
}

/// Extract auth state from request
pub async fn auth_middleware(
    State(auth_middleware): State<AuthMiddleware>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Bearer token from Authorization header. When SSO is
    // enabled we try at+jwt first (EdDSA, signed by mokosh-auth);
    // failing that we fall back to the legacy HS256 path. The fallback
    // is what keeps existing sessions working during transition.
    let auth_state = match bearer(&request) {
        Some(token) => {
            // 1. SSO at+jwt path.
            let from_sso = auth_middleware
                .at_jwt
                .as_ref()
                .and_then(|v| v.try_verify(token));
            if let Some(verified) = from_sso {
                let tenant_id = verified.tenant_id;
                let user = current_user_from_at_jwt(&verified);
                AuthState::authenticated(user, tenant_id)
            } else {
                // 2. Legacy HS256 path.
                match auth_middleware.auth_service.decode_token(token) {
                    Ok(claims) => match auth_middleware
                        .auth_service
                        .get_user_by_id(claims.sub)
                        .await
                    {
                        Ok(user) => AuthState::authenticated(user.to_current_user(), claims.tid),
                        Err(_) => AuthState::default(),
                    },
                    Err(_) => AuthState::default(),
                }
            }
        }
        None => AuthState::default(),
    };

    // Insert auth state into request extensions
    request.extensions_mut().insert(auth_state);

    next.run(request).await
}

fn bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
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

/// Tenant scope for a protected handler.
///
/// This extractor is the recommended way to access a tenant id inside a
/// handler. The audit (PMS-23, cross-cutting #8) called out that every
/// service method takes `tenant_id: Uuid`, but until now there was
/// nothing in the route signature making it obvious where that id
/// comes from — handlers were copying `user.tenant_id` by hand, and a
/// new handler that forgot would have leaked across tenants.
///
/// Use it like `RequireAuth`:
/// ```ignore
/// async fn list_tickets(
///     scope: TenantScope,
///     ...
/// ) -> AppResult<Json<...>> {
///     state.ticket_service.list_tickets(scope.tenant_id, ...).await
/// }
/// ```
///
/// The `tenant_id` field is hard-bound to the authenticated user's
/// claim; handlers that need to switch tenants (super-admin only) must
/// take an additional path / query parameter and gate it on role.
#[derive(Clone, Debug)]
pub struct TenantScope {
    pub tenant_id: uuid::Uuid,
    pub user: CurrentUser,
}

impl<S> axum::extract::FromRequestParts<S> for TenantScope
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
            Some(user) => Ok(TenantScope {
                tenant_id: user.tenant_id,
                user,
            }),
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
