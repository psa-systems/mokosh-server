//! Authentication middleware for Axum

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use super::oidc_rs::Verifier as BunyipVerifier;
use super::{AuthService, AuthState, CurrentUser, UserRole};
use crate::utils::error::AppError;

/// Extension to hold the current auth state
#[derive(Clone)]
pub struct AuthMiddleware {
    pub auth_service: Arc<AuthService>,
    /// Optional Resource-Server verifier for the bunyip-as-OP cutover.
    /// When set, the middleware verifies Bearer tokens against bunyip-api's
    /// JWKS first; on success it JIT-mirrors the (sub, email) into the local
    /// users table. See docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md.
    pub bunyip: Option<Arc<BunyipVerifier>>,
    /// Optional tenant service used by the bunyip path to provision a user's
    /// personal tenant on self-signup (PMS-244). When unset, the bunyip path
    /// falls back to the single default tenant.
    pub tenants: Option<Arc<crate::modules::tenants::TenantService>>,
    /// Optional invitations service: the bunyip path resolves a pending invite
    /// for the user's email and places/re-homes them into that tenant (PMS-244).
    pub invitations: Option<Arc<crate::modules::invitations::InvitationsService>>,
}

impl AuthMiddleware {
    pub fn new(auth_service: AuthService) -> Self {
        Self {
            auth_service: Arc::new(auth_service),
            bunyip: None,
            tenants: None,
            invitations: None,
        }
    }

    /// Attach the bunyip-as-OP Resource-Server verifier. Call this at startup
    /// once `OIDC_ISSUER` + `OIDC_AUDIENCE` are set; see `oidc_rs::VerifierConfig`.
    pub fn with_bunyip(mut self, verifier: BunyipVerifier) -> Self {
        self.bunyip = Some(Arc::new(verifier));
        self
    }

    /// Wire the tenant service so the bunyip path can provision a user's
    /// personal tenant on self-signup (PMS-244).
    pub fn with_tenants(mut self, tenants: Arc<crate::modules::tenants::TenantService>) -> Self {
        self.tenants = Some(tenants);
        self
    }

    /// Wire the invitations service so the bunyip path resolves a pending invite
    /// into a tenant placement on login (PMS-244).
    pub fn with_invitations(
        mut self,
        invitations: Arc<crate::modules::invitations::InvitationsService>,
    ) -> Self {
        self.invitations = Some(invitations);
        self
    }
}

/// Extract auth state from request
pub async fn auth_middleware(
    State(auth_middleware): State<AuthMiddleware>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Bearer token from Authorization header. The bunyip-as-OP
    // Resource-Server path is tried first; failing that we fall back to the
    // legacy HS256 cookie path. The fallback keeps existing sessions working.
    let auth_state = match bearer(&request) {
        Some(token) => {
            // 1. Bunyip-as-OP Resource-Server path (new). Tokens minted by
            //    bunyip-api carry typ=at+jwt + iss=bunyip's OIDC_ISSUER.
            let from_bunyip = match auth_middleware.bunyip.as_ref() {
                Some(v) => match v.verify_at_jwt(token).await {
                    Ok(claims) => {
                        ensure_user_from_bunyip(
                            &auth_middleware.auth_service,
                            auth_middleware.tenants.as_ref(),
                            auth_middleware.invitations.as_ref(),
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
            } else {
                // 2. Legacy HS256 cookie path. Only an `access` token is a
                // valid Bearer credential; `decode_token` runs
                // `Validation::default()` and does not assert `typ`, so a
                // `typ:"refresh"` token would otherwise be accepted here.
                // Guard it explicitly, mirroring `refresh_token()`.
                match auth_middleware.auth_service.decode_token(token) {
                    Ok(claims) if claims.typ == "access" => match auth_middleware
                        .auth_service
                        .get_user_by_id(claims.tid, claims.sub)
                        .await
                    {
                        Ok(user) => AuthState::authenticated(user.to_current_user(), claims.tid),
                        Err(_) => AuthState::default(),
                    },
                    _ => AuthState::default(),
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
///     state.ticket_service.list_ticket_responses(scope.tenant_id, ...).await
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

/// PMS-479: `RequireAdmin` + `RequireAuth` collapsed into one
/// extractor. Saves the `RequireAuth(u): RequireAuth, _admin: RequireAdmin`
/// pair from spelling out the role guard alongside the user grab
/// every admin-gated handler had to spell out before. Yields the
/// `CurrentUser` directly via `RequireAdminUser(user): RequireAdminUser`.
#[derive(Clone)]
pub struct RequireAdminUser(pub CurrentUser);

impl<S> axum::extract::FromRequestParts<S> for RequireAdminUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Delegate to RequireAdmin so the role list stays a single
        // source of truth. Unwrap the tuple to drop the PhantomData
        // tail; consumers only ever want the user.
        let RequireRole(user, _) = RequireAdmin::from_request_parts(parts, state).await?;
        Ok(Self(user))
    }
}

/// Super-admin role requirement. The narrowest gate: only the platform
/// operator role, never a tenant `admin`. Use it for cross-tenant
/// administrative surfaces (e.g. the `/tenants` CRUD routes) so the
/// "super admin only" rule lives in the route signature instead of a
/// hand-rolled `if user.role != UserRole::SuperAdmin` block in every
/// handler (PMS-198).
pub struct SuperAdminRoles;
impl RoleRequirement for SuperAdminRoles {
    fn allowed_roles() -> &'static [&'static str] {
        &["super_admin"]
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
pub type RequireSuperAdmin = RequireRole<SuperAdminRoles>;
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
    tenants: Option<&Arc<crate::modules::tenants::TenantService>>,
    invitations: Option<&Arc<crate::modules::invitations::InvitationsService>>,
    verifier: &BunyipVerifier,
    bearer: &str,
    claims: &super::oidc_rs::AtClaims,
) -> Option<AuthState> {
    let sub = uuid::Uuid::parse_str(&claims.sub).ok()?;

    // PMS-244: orgs live in Mokosh (Bunyip is a personal-subscription IdP with
    // no org concept), so the tenant is resolved from Mokosh's own membership
    // state, NOT a token claim. Priority: a pending invite for the user's
    // verified email wins; else their existing placement; else a brand-new user
    // gets their own `personal` tenant (self-signup). Email comes from
    // /oauth2/userinfo (the at+jwt carries no email claim).
    let info = verifier.userinfo(bearer).await;
    let email = info.as_ref().and_then(|i| i.email.clone());
    let email_verified = info
        .as_ref()
        .and_then(|i| i.email_verified)
        .unwrap_or(false);
    // BUNYIP-141: standard profile claims off the same userinfo round-trip.
    // Bunyip emits them only when the at+jwt's scope set covers `profile`
    // AND the bunyip-side column is non-NULL (BUNYIP-140); absent here means
    // either "scope not requested" or "user has not filled it in", in both
    // cases the JIT path falls back to `synthetic_name_from_email`.
    let given_name = info.as_ref().and_then(|i| i.given_name.clone());
    let family_name = info.as_ref().and_then(|i| i.family_name.clone());

    place_bunyip_user(
        auth_service,
        tenants,
        invitations,
        sub,
        email,
        email_verified,
        given_name,
        family_name,
        claims,
    )
    .await
}

/// PMS-249: the testable core of the bunyip login path. Given the verified
/// `sub` plus the `email` / `email_verified` resolved from userinfo, resolve
/// which Mokosh tenant the user belongs to (invite > existing placement >
/// personal self-signup, with the PMS-245 default-tenant backfill), JIT-mirror
/// the user, accept any consumed invite, reconcile the Bunyip role, and return
/// the `AuthState`. Split out of [`ensure_user_from_bunyip`] (which owns the
/// verifier / userinfo call) so this placement logic is integration-testable
/// without a live OIDC verifier.
// BUNYIP-141: `place_bunyip_user`'s arg count is one over clippy's default
// threshold (8 vs 7) because each `email_verified` / `given_name` /
// `family_name` value is read straight off the userinfo response and bundling
// them into a synthetic struct would force every call site (production + 7
// integration tests) to construct that struct from the same fields. Suppress
// here rather than refactor; the surface is internal to the auth module.
#[allow(clippy::too_many_arguments)]
pub async fn place_bunyip_user(
    auth_service: &Arc<AuthService>,
    tenants: Option<&Arc<crate::modules::tenants::TenantService>>,
    invitations: Option<&Arc<crate::modules::invitations::InvitationsService>>,
    sub: uuid::Uuid,
    email: Option<String>,
    email_verified: bool,
    given_name: Option<String>,
    family_name: Option<String>,
    claims: &super::oidc_rs::AtClaims,
) -> Option<AuthState> {
    let placement = auth_service.find_user_placement(sub).await.ok().flatten();
    let current = placement.as_ref().map(|(t, _)| *t);

    // An invite to address X is consumed only by a Bunyip user with verified X.
    let invite = match (invitations, email.as_deref()) {
        (Some(invs), Some(em)) if email_verified => {
            invs.newest_pending_for(em).await.ok().flatten()
        }
        _ => None,
    };

    // PMS-245: a non-admin user still parked in the shared default tenant (dumped
    // there by the pre-PMS-244 funnel) is treated like a fresh user - moved to
    // their own personal tenant - so nobody stays stuck sharing it.
    let stuck_in_default = is_stuck_in_default(
        current,
        default_bunyip_tenant_id(),
        placement.as_ref().map(|(_, r)| r.as_str()).unwrap_or(""),
        invite.is_some(),
    );

    let target = if let Some(inv) = invite.as_ref() {
        inv.tenant_id
    } else if let Some(t) = current.filter(|_| !stuck_in_default) {
        t
    } else {
        // Brand-new user (or one being backfilled off the default tenant), no
        // invite: provision their own personal tenant.
        match tenants {
            Some(svc) => match svc.ensure_personal_tenant(sub).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, sub = %sub, "personal tenant provisioning failed");
                    return None;
                }
            },
            None => default_bunyip_tenant_id(),
        }
    };

    // PMS-288: the target tenant may have been provisioned off the PSA path - an
    // invite into an auth/SSO-created org tenant, or an existing placement in a
    // manually-created tenant - and so never received `copy_default_config`,
    // leaving ticket creation (which needs a default ticket status + a sequence
    // row) to 500. Seed it idempotently now that `target` is resolved. The
    // personal-tenant branch above already seeded via `ensure_personal_tenant`,
    // so this is a no-op there. Best-effort: a seed failure is logged, not fatal
    // to the request (a tenant lacking config still authenticates).
    if let Some(svc) = tenants {
        if let Err(e) = svc.ensure_default_config(target).await {
            tracing::warn!(error = %e, sub = %sub, tenant_id = %target, "default config seed failed");
        }
    }

    // Re-home an already-placed user into the target tenant - invite acceptance,
    // or the PMS-243 backfill out of the legacy default tenant. Idempotent (a
    // no-op when they are already there); co-mingled data stays put (PMS-243).
    if let Some(cur) = current {
        if cur != target {
            match auth_service
                .rehome_user_between_tenants(sub, cur, target)
                .await
            {
                Ok(true) => {
                    tracing::info!(sub = %sub, tenant_id = %target, "re-homed user into tenant")
                }
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, sub = %sub, "user re-home failed"),
            }
        }
    }

    // Resolve the local shadow row, JIT-creating it on first sight. A brand-new
    // invited user is seeded with the invite's role; otherwise the user owns
    // their own single-tenant Mokosh world (PMS-447) so the JIT default is
    // `Admin`, not `Technician`. The Bunyip-role reconciliation below still
    // runs and promotes to `SuperAdmin` if the at+jwt carries the platform
    // admin claim.
    let initial_role = invite
        .as_ref()
        .and_then(|i| UserRole::from_str(&i.role))
        .unwrap_or(UserRole::Admin);
    let mut user = match auth_service.get_user_by_id(target, sub).await {
        Ok(user) => user,
        Err(_) => {
            // Persist the IdP-supplied email on the JIT insert ONLY when the
            // IdP reports it verified, matching the Google path.
            // `upsert_user_from_oidc` stamps `email_verified_at = NOW()`, so
            // writing an unverified address here would falsely mark it
            // verified and open an auto-link/capture path against the real
            // owner. An unverified user is still self-signed-up (into their
            // own isolated personal tenant) under a placeholder address; the
            // real email is backfilled on a later login once verified.
            let email_for_insert = match (email.clone(), email_verified) {
                (Some(em), true) => em,
                _ => format!("{sub}@unresolved.invalid"),
            };
            // BUNYIP-141: hand the userinfo profile claims to the JIT path
            // so a bunyip-provisioned user lands with their real name on
            // first sight. Both are Option<String>; None falls back to
            // `synthetic_name_from_email` inside the service.
            auth_service
                .upsert_user_from_oidc(
                    sub,
                    target,
                    &email_for_insert,
                    initial_role,
                    given_name.as_deref(),
                    family_name.as_deref(),
                )
                .await
                .map_err(|e| tracing::warn!(error = %e, sub = %sub, "JIT user upsert failed"))
                .ok()?
        }
    };

    // Mark the invite accepted now the user is placed (best-effort).
    if let (Some(invs), Some(inv)) = (invitations, invite.as_ref()) {
        let _ = invs.accept(inv.id, sub).await;
    }

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
    // PMS-458: an explicit invite role is the inviting admin's deliberate,
    // least-privilege grant into a SHARED org tenant. The PMS-447 single-tenancy
    // admin floor assumes the signed-in user owns their own one-person tenant,
    // which is false for an invited joiner, so that floor must NOT silently
    // elevate the invite role (e.g. `manager` -> `admin`). When this placement
    // is consuming a fresh invite the invite role stands as-is; only a
    // platform-level Bunyip `admin` claim (genuinely cross-tenant) still
    // overrides to `super_admin`. Non-invite placements keep the PMS-447 floor.
    let effective = if invite.is_some() {
        match claims.bunyip_role.as_deref() {
            Some("admin") => UserRole::SuperAdmin,
            _ => user.role,
        }
    } else {
        effective_role_from_bunyip(claims.bunyip_role.as_deref(), user.role)
    };
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
/// effective role on the Bunyip RS path (PMS-172, revised for the
/// single-tenancy posture in PMS-447).
///
/// After PMS-447 each Mokosh tenant has exactly one user (the owner), so a
/// signed-in Bunyip user IS the admin of their own world by construction:
/// - `admin`      -> mokosh `super_admin` (platform-level, cross-tenant; the
///   only role that is genuinely Bunyip-exclusive).
/// - `subscriber` -> mokosh `admin` (single-tenancy floor). A stale local
///   `super_admin` clamps down to `admin`; anything lower than `admin`
///   (Technician, Manager, etc.) upgrades up to `admin`.
/// - any other / unknown value -> treated like `subscriber`. A future Bunyip
///   role can't silently grant super_admin before mokosh learns to map it,
///   but it still satisfies the single-tenancy floor.
/// - absent claim (`None`) -> keep the local role unchanged. Back-compatible:
///   the legacy HS256 / standalone paths (which never carry the claim) are
///   unaffected.
fn effective_role_from_bunyip(bunyip_role: Option<&str>, local: UserRole) -> UserRole {
    match bunyip_role {
        None => local,
        Some("admin") => UserRole::SuperAdmin,
        Some(_) => {
            // PMS-447: subscriber (or unknown future role) -> tenant admin.
            // super_admin is Bunyip-exclusive, so a stale local super_admin
            // clamps down to admin; anything else rises to admin.
            UserRole::Admin
        }
    }
}

fn default_bunyip_tenant_id() -> uuid::Uuid {
    std::env::var("OIDC_DEFAULT_TENANT_ID")
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(&s).ok())
        .unwrap_or_else(|| uuid::Uuid::from_u128(1))
}

/// PMS-245: whether an already-placed user should be backfilled off the shared
/// default landing tenant into their own personal tenant. True only for a user
/// currently in `default_tenant`, with no pending invite, who is not a platform
/// `super_admin` (those legitimately belong to the infra/default tenant).
fn is_stuck_in_default(
    current: Option<uuid::Uuid>,
    default_tenant: uuid::Uuid,
    role: &str,
    has_invite: bool,
) -> bool {
    current == Some(default_tenant) && !has_invite && role != "super_admin"
}

#[cfg(test)]
mod tests {
    use super::{
        default_bunyip_tenant_id, effective_role_from_bunyip, is_stuck_in_default, UserRole,
    };
    use uuid::Uuid;

    #[test]
    fn backfill_only_non_admin_default_tenant_users_without_invite() {
        let default = default_bunyip_tenant_id();
        let other = Uuid::from_u128(99);

        // The target case: a technician parked in the default tenant, no invite.
        assert!(is_stuck_in_default(
            Some(default),
            default,
            "technician",
            false
        ));
        // Exemptions:
        assert!(
            !is_stuck_in_default(Some(default), default, "super_admin", false),
            "super_admins stay in the infra tenant"
        );
        assert!(
            !is_stuck_in_default(Some(default), default, "technician", true),
            "an invite takes precedence - it decides the tenant"
        );
        assert!(
            !is_stuck_in_default(Some(other), default, "technician", false),
            "a user already in a real tenant is left alone"
        );
        assert!(
            !is_stuck_in_default(None, default, "", false),
            "a brand-new user has no current placement to back-fill"
        );
    }

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
    fn subscriber_floors_local_role_to_tenant_admin() {
        // PMS-447: every signed-in Bunyip user owns their single-tenant Mokosh
        // world, so a `subscriber` claim always floors at `Admin` regardless
        // of the stored local role - tenant-internal demotions below admin
        // (Technician, Manager, etc.) do not survive token reconciliation.
        for local in [
            UserRole::Technician,
            UserRole::Dispatcher,
            UserRole::Sales,
            UserRole::Finance,
            UserRole::Manager,
            UserRole::Admin,
        ] {
            assert_eq!(
                effective_role_from_bunyip(Some("subscriber"), local),
                UserRole::Admin
            );
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
    fn unknown_bunyip_role_floors_to_admin_and_clamps_super_admin() {
        // A future / unrecognized Bunyip role must not silently grant
        // super_admin, but it still satisfies the PMS-447 single-tenancy
        // floor: the signed-in user is an admin in their own Mokosh.
        assert_eq!(
            effective_role_from_bunyip(Some("owner"), UserRole::Technician),
            UserRole::Admin
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
