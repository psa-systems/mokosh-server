//! Authentication middleware for Axum

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use super::at_jwt::{current_user_from_at_jwt, AtJwtVerifier};
use super::oidc_rs::Verifier as BunyipVerifier;
use super::{AuthService, AuthState, CurrentUser, UserRole};
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
    /// Optional Resource-Server verifier for the bunyip-as-OP cutover.
    /// When set, the middleware verifies Bearer tokens against bunyip-api's
    /// JWKS first; on success it JIT-mirrors the (sub, email) into the local
    /// users table. See docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md.
    pub bunyip: Option<Arc<BunyipVerifier>>,
}

impl AuthMiddleware {
    pub fn new(auth_service: AuthService) -> Self {
        Self {
            auth_service: Arc::new(auth_service),
            at_jwt: None,
            bunyip: None,
        }
    }

    /// Attach an `at+jwt` verifier. Call this once at startup with the
    /// `OidcKeySet` returned from `mokosh_auth::bootstrap`.
    pub fn with_at_jwt(mut self, verifier: AtJwtVerifier) -> Self {
        self.at_jwt = Some(verifier);
        self
    }

    /// Attach the bunyip-as-OP Resource-Server verifier. Call this at startup
    /// once `OIDC_ISSUER` + `OIDC_AUDIENCE` are set; see `oidc_rs::VerifierConfig`.
    pub fn with_bunyip(mut self, verifier: BunyipVerifier) -> Self {
        self.bunyip = Some(Arc::new(verifier));
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
            // 1. Bunyip-as-OP Resource-Server path (new). Tokens minted by
            //    bunyip-api carry typ=at+jwt + iss=bunyip's OIDC_ISSUER.
            let from_bunyip = match auth_middleware.bunyip.as_ref() {
                Some(v) => match v.verify_at_jwt(token).await {
                    Ok(claims) => {
                        ensure_user_from_bunyip(
                            &auth_middleware.auth_service,
                            v.as_ref(),
                            token,
                            &claims,
                        )
                        .await
                    }
                    Err(_) => None,
                },
                None => None,
            };
            if let Some(state) = from_bunyip {
                state
            } else if let Some(verified) = auth_middleware
                .at_jwt
                .as_ref()
                .and_then(|v| v.try_verify(token))
            {
                // 2. Legacy SSO at+jwt path (mokosh-auth IdP - transitional).
                let tenant_id = verified.tenant_id;
                let user = current_user_from_at_jwt(&verified);
                AuthState::authenticated(user, tenant_id)
            } else {
                // 3. Legacy HS256 cookie path.
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

// ── Bunyip RS helper ─────────────────────────────────────────────────────────

/// Resolve a Bunyip-issued at+jwt claim set into an `AuthState`.
///
/// First looks up the local users row by `claims.sub` (which equals bunyip's
/// internal user UUID). On first sight of a new sub, calls bunyip's
/// `/oauth2/userinfo` to get `email`, then JIT-inserts a row into
/// `public.users`.
///
/// `tenant_id` falls back to `OIDC_DEFAULT_TENANT_ID` (or the all-zeros UUID
/// with a 1 in the low bits, matching `auth::bootstrap::default_tenant_id`)
/// per docs §3.3: multi-tenant claim plumbing is out of scope for v1.
///
/// Returns `None` only when the user can't be resolved AND can't be created.
/// The caller treats `None` as "drop the bunyip path" and falls back to legacy.
async fn ensure_user_from_bunyip(
    auth_service: &Arc<AuthService>,
    verifier: &BunyipVerifier,
    bearer: &str,
    claims: &super::oidc_rs::AtClaims,
) -> Option<AuthState> {
    let sub = uuid::Uuid::parse_str(&claims.sub).ok()?;

    // Happy path: row already exists.
    if let Ok(user) = auth_service.get_user_by_id(sub).await {
        let tenant_id = user.tenant_id;
        return Some(AuthState::authenticated(user.to_current_user(), tenant_id));
    }

    // JIT path: fetch email from /oauth2/userinfo and insert.
    let info = verifier.userinfo(bearer).await;
    let email = info
        .as_ref()
        .and_then(|i| i.email.clone())
        .unwrap_or_else(|| format!("{sub}@unresolved.invalid"));
    let tenant_id = default_bunyip_tenant_id();

    let user = auth_service
        .upsert_user_from_oidc(sub, tenant_id, &email, UserRole::default())
        .await
        .map_err(|e| tracing::warn!(error = %e, sub = %sub, "JIT user upsert failed"))
        .ok()?;
    Some(AuthState::authenticated(user.to_current_user(), tenant_id))
}

fn default_bunyip_tenant_id() -> uuid::Uuid {
    std::env::var("OIDC_DEFAULT_TENANT_ID")
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(&s).ok())
        .unwrap_or_else(|| uuid::Uuid::from_u128(1))
}
