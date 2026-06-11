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
                        .get_user_by_id(claims.tid, claims.sub)
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
    pub tenant_id: super::tenant::TenantId,
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
                tenant_id: super::tenant::TenantScoped::tenant(&user),
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

// PMS-113 AC3: per-tenant module enable/disable runtime gate ----------------

/// Trait carrying the static module name a `RequireModuleEnabled<G>`
/// gate checks. One unit struct + one trait impl per gated module.
/// The blanket `FromRequestParts` below does the DB lookup.
pub trait ModuleGate: Send + Sync + 'static {
    const NAME: &'static str;
}

/// Extractor that authenticates the caller AND verifies their tenant
/// has the named module enabled via `module_config.is_enabled`. When
/// the module is disabled (or has no row), returns `404 NotFound` so a
/// probing client can't distinguish a disabled feature from an
/// unmounted route. PMS-113 AC3.
///
/// Use the per-module type aliases below (`RequireBilling`, etc.) so
/// the module name is compile-time bound to the extractor type, not a
/// magic string in every handler signature.
///
/// **Core modules are NOT gated.** `ticketing`, `contacts`,
/// `notifications`, and portal authentication keep working regardless
/// of `module_config.is_enabled`. The gateable taxonomy is
/// `billing`, `projects`, `calendar`, `contracts`, `assets`,
/// `knowledge_base`, `rmm_integration`, `reports`, `time_tracking`.
///
/// The extractor reads an `Arc<SettingsService>` from the request's
/// extensions; `create_api_router` adds it via `.layer(Extension(...))`.
#[derive(Clone, Debug)]
pub struct RequireModuleEnabled<G: ModuleGate> {
    pub user: CurrentUser,
    _gate: std::marker::PhantomData<G>,
}

impl<G: ModuleGate, S> axum::extract::FromRequestParts<S> for RequireModuleEnabled<G>
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // First require authentication; share the same AuthState path
        // as RequireAuth so misconfigured handlers fail-closed on auth
        // before ever touching the gate.
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .cloned()
            .unwrap_or_default();
        let user = match auth_state.user {
            Some(u) => u,
            None => return Err(AppError::Unauthorized),
        };

        // Read the SettingsService from request extensions. Wired in
        // via `.layer(Extension(settings_service))` on the API v1
        // router; if the layer is missing this fails to compile-link
        // at runtime (which is acceptable - the router setup is one
        // place, easy to spot).
        let settings = parts
            .extensions
            .get::<std::sync::Arc<crate::modules::settings::SettingsService>>()
            .cloned()
            .ok_or_else(|| {
                AppError::Internal(
                    "SettingsService extension missing; routing wiring bug".to_string(),
                )
            })?;

        let enabled = settings
            .is_module_enabled(super::tenant::TenantScoped::tenant(&user), G::NAME)
            .await?;
        if !enabled {
            return Err(AppError::NotFound(format!("module {}", G::NAME)));
        }
        Ok(Self {
            user,
            _gate: std::marker::PhantomData,
        })
    }
}

/// Declare a gated module: defines a unit struct, implements
/// `ModuleGate` on it, and exposes a `RequireFoo` type alias for the
/// extractor.
macro_rules! gated_module {
    ($struct_name:ident, $module_name:expr, $alias:ident) => {
        pub struct $struct_name;
        impl ModuleGate for $struct_name {
            const NAME: &'static str = $module_name;
        }
        pub type $alias = RequireModuleEnabled<$struct_name>;
    };
}

gated_module!(BillingModule, "billing", RequireBilling);
gated_module!(ProjectsModule, "projects", RequireProjects);
gated_module!(CalendarModule, "calendar", RequireCalendar);
gated_module!(ContractsModule, "contracts", RequireContracts);
gated_module!(AssetsModule, "assets", RequireAssets);
gated_module!(KnowledgeBaseModule, "knowledge_base", RequireKnowledgeBase);
gated_module!(RmmModule, "rmm_integration", RequireRmm);
gated_module!(ReportsModule, "reports", RequireReports);
gated_module!(TimeTrackingModule, "time_tracking", RequireTimeTracking);

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

    // Resolve the local shadow row, JIT-creating it on first sight. The
    // bunyip-issued at+jwt does not (yet) carry a tenant claim, so we use the
    // default bunyip tenant. If multi-tenant claim plumbing lands we revisit
    // this. PMS-4 AC6 + docs §3.3.
    let default_tenant = default_bunyip_tenant_id();
    let mut user = match auth_service.get_user_by_id(default_tenant, sub).await {
        Ok(user) => user,
        Err(_) => {
            // JIT path: fetch email from /oauth2/userinfo and insert.
            let info = verifier.userinfo(bearer).await;
            let email = info
                .as_ref()
                .and_then(|i| i.email.clone())
                .unwrap_or_else(|| format!("{sub}@unresolved.invalid"));
            auth_service
                .upsert_user_from_oidc(sub, default_tenant, &email, UserRole::default())
                .await
                .map_err(|e| tracing::warn!(error = %e, sub = %sub, "JIT user upsert failed"))
                .ok()?
        }
    };

    // PMS-172: Bunyip governs the top role. Translate the `bunyip_role` claim
    // into mokosh's taxonomy. The translated `effective` role is the
    // AUTHORITATIVE authorization for this request (it is derived from the
    // already-verified at+jwt, so it is exactly the caller's entitlement); the
    // `set_user_role` write below is best-effort PERSISTENCE only, kept so the
    // DB stays accurate for joins/audit/reporting. A failed write therefore
    // does NOT under- or over-grant: the request still runs with `effective`,
    // and the next request re-derives and re-syncs. When the claim is absent
    // the effective role equals the local role, so this is a no-op for legacy /
    // standalone tokens.
    if let Some(raw) = claims.bunyip_role.as_deref() {
        if raw != "admin" && raw != "subscriber" {
            tracing::debug!(
                user = %user.id,
                bunyip_role = %raw,
                "unrecognized bunyip_role claim value; treating as non-admin"
            );
        }
    }
    let effective = effective_role_from_bunyip(claims.bunyip_role.as_deref(), user.role);
    if effective != user.role {
        // Role transitions are security-relevant; log every one (fires only on
        // change, so low volume) so an elevation/demotion is observable even
        // though this reconciliation writes no audit-table row (the actor is
        // the login itself, not an operator request carrying an AuditCtx). A
        // first-class audit row would need request-context plumbing; tracked as
        // a follow-up.
        tracing::info!(
            user = %user.id,
            from = %user.role.as_str(),
            to = %effective.as_str(),
            bunyip_role = ?claims.bunyip_role.as_deref(),
            "reconciling user role from Bunyip claim"
        );
        if let Err(e) = auth_service
            .set_user_role(user.tenant_id, user.id, effective)
            .await
        {
            tracing::warn!(error = %e, user = %user.id, "failed to persist bunyip-derived role (request still uses it)");
        }
        user.role = effective;
    }

    let tenant_id = user.tenant_id;
    Some(AuthState::authenticated(user.to_current_user(), tenant_id))
}

/// Translate Bunyip's system role (the `bunyip_role` claim) into mokosh's
/// effective role on the Bunyip RS path (PMS-172).
///
/// Bunyip is the SSO / identity manager and governs only the top role:
/// - `admin`      -> mokosh `super_admin` (authoritative).
/// - `subscriber` -> the user's locally-assigned mokosh role, EXCEPT that
///   `super_admin` is Bunyip-exclusive, so a stale / locally-set `super_admin`
///   is clamped down to `admin`.
/// - any other / unknown value -> treated like `subscriber` (never elevates,
///   still clamps a stale `super_admin`), so a future Bunyip role can't
///   silently grant super_admin before mokosh learns to map it.
/// - absent claim (`None`) -> keep the local role unchanged. Back-compatible:
///   mokosh can ship before Bunyip emits the claim, and the legacy HS256 /
///   standalone paths (which never carry the claim) are unaffected.
fn effective_role_from_bunyip(bunyip_role: Option<&str>, local: UserRole) -> UserRole {
    match bunyip_role {
        None => local,
        Some("admin") => UserRole::SuperAdmin,
        Some(_) => {
            // subscriber (or an unknown future value): super_admin is
            // Bunyip-exclusive, everything below it is mokosh-internal.
            if local == UserRole::SuperAdmin {
                UserRole::Admin
            } else {
                local
            }
        }
    }
}

fn default_bunyip_tenant_id() -> uuid::Uuid {
    std::env::var("OIDC_DEFAULT_TENANT_ID")
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(&s).ok())
        .unwrap_or_else(|| uuid::Uuid::from_u128(1))
}

#[cfg(test)]
mod tests {
    use super::{effective_role_from_bunyip, UserRole};

    #[test]
    fn bunyip_admin_maps_to_super_admin() {
        // A Bunyip admin is the top mokosh role regardless of the local row.
        for local in [
            UserRole::Technician,
            UserRole::Manager,
            UserRole::Admin,
            UserRole::SuperAdmin,
        ] {
            assert_eq!(
                effective_role_from_bunyip(Some("admin"), local),
                UserRole::SuperAdmin
            );
        }
    }

    #[test]
    fn subscriber_uses_local_role() {
        for local in [
            UserRole::Technician,
            UserRole::Dispatcher,
            UserRole::Sales,
            UserRole::Finance,
            UserRole::Manager,
            UserRole::Admin,
        ] {
            assert_eq!(effective_role_from_bunyip(Some("subscriber"), local), local);
        }
    }

    #[test]
    fn subscriber_clamps_stale_super_admin_to_admin() {
        // super_admin is Bunyip-exclusive: a subscriber can never carry it,
        // even if the local row was left at super_admin.
        assert_eq!(
            effective_role_from_bunyip(Some("subscriber"), UserRole::SuperAdmin),
            UserRole::Admin
        );
    }

    #[test]
    fn unknown_bunyip_role_does_not_elevate_and_clamps_super_admin() {
        // A future / unrecognized Bunyip role must not silently grant
        // super_admin, and must still strip a stale local super_admin.
        assert_eq!(
            effective_role_from_bunyip(Some("owner"), UserRole::Technician),
            UserRole::Technician
        );
        assert_eq!(
            effective_role_from_bunyip(Some("owner"), UserRole::SuperAdmin),
            UserRole::Admin
        );
    }

    #[test]
    fn absent_claim_keeps_local_role_unchanged() {
        // Back-compat: no claim (legacy / standalone / pre-BUNYIP-66) leaves
        // the local role exactly as-is, including a local super_admin.
        for local in [
            UserRole::Technician,
            UserRole::Manager,
            UserRole::Admin,
            UserRole::SuperAdmin,
        ] {
            assert_eq!(effective_role_from_bunyip(None, local), local);
        }
    }
}
