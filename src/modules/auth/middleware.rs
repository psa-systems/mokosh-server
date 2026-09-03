//! Authentication middleware for Axum

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use super::oidc_rs::{Verifier as BunyipVerifier, VerifyError};
use super::service::{is_unresolved_placeholder_email, BunyipPrincipal, UNRESOLVED_EMAIL_DOMAIN};
use super::{AuthService, AuthState, CurrentUser, UserRole};
use crate::utils::error::AppError;

/// PMS-769: what happened to the `Authorization: Bearer` credential on this
/// request. Recorded on the request extensions by [`auth_middleware`] (and by
/// the portal middleware) so the extractors can render the RFC 6750
/// `WWW-Authenticate` challenge that matches the actual failure instead of a
/// single opaque 401.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BearerOutcome {
    /// No `Authorization: Bearer` header was presented.
    #[default]
    Absent,
    /// A bearer was presented and accepted by one of the auth paths.
    Accepted,
    /// A bearer was presented and rejected because it had expired.
    Expired,
    /// A bearer was presented and rejected for any other reason (bad
    /// signature, wrong audience, unknown kid, unusable principal, ...).
    Rejected,
}

impl BearerOutcome {
    /// Classify a bunyip verification failure. Only `Expired` is singled out;
    /// every other variant is an ordinary `invalid_token` rejection as far as
    /// RFC 6750 section 3.1 is concerned.
    fn from_verify_error(error: &VerifyError) -> Self {
        match error {
            VerifyError::Expired => Self::Expired,
            _ => Self::Rejected,
        }
    }

    /// The `WWW-Authenticate` value a 401 for this outcome must carry
    /// (RFC 6750 section 3).
    fn challenge(self) -> &'static str {
        match self {
            Self::Expired => {
                r#"Bearer error="invalid_token", error_description="The access token expired""#
            }
            Self::Rejected => r#"Bearer error="invalid_token""#,
            // No credential was presented (or one was accepted and the 401
            // came from somewhere else): the bare challenge just names the
            // scheme the resource server expects.
            Self::Absent | Self::Accepted => "Bearer",
        }
    }
}

/// PMS-769: extractor rejection for the credential gates. Renders exactly the
/// same `AppError` envelope as before and adds the RFC 6750 challenge when the
/// 401 actually concerns a bearer credential. Kept out of
/// `impl IntoResponse for AppError` on purpose: the webhook HMAC gates and the
/// portal password checks also return `AppError::Unauthorized` and must stay
/// challenge-free.
#[derive(Debug)]
pub struct AuthRejection {
    error: AppError,
    challenge: Option<&'static str>,
}

impl AuthRejection {
    /// A 401 raised by a credential gate: carries the challenge for `outcome`.
    pub(crate) fn challenged(error: AppError, outcome: BearerOutcome) -> Self {
        Self {
            error,
            challenge: Some(outcome.challenge()),
        }
    }
}

impl From<AppError> for AuthRejection {
    /// Errors an extractor raises *after* the credential resolved (403
    /// Forbidden, the 404 module gate, the 500 wiring bug) never concern a
    /// bearer, so they render unchanged with no challenge. This also carries
    /// the `?` conversions inside the extractor bodies.
    fn from(error: AppError) -> Self {
        Self {
            error,
            challenge: None,
        }
    }
}

impl From<AuthRejection> for AppError {
    /// Reverse conversion so extractors whose own `Rejection` is
    /// `AppError` can use `?` on a call that returns `AuthRejection`
    /// (e.g. `RequireAuth::from_request_parts`). The RFC 6750
    /// challenge is dropped, which is correct: an extractor whose
    /// rejection is `AppError` never attaches a challenge anyway,
    /// so the response shape is identical to the direct-`AppError`
    /// path it was already using before the merge.
    fn from(rejection: AuthRejection) -> Self {
        rejection.error
    }
}

impl axum::response::IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let mut response = self.error.into_response();
        if let Some(challenge) = self.challenge {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(challenge),
            );
        }
        response
    }
}

/// Read the bearer outcome the middleware recorded. Defaults to `Absent`, so a
/// route somehow mounted without the middleware still answers a bare `Bearer`
/// challenge rather than claiming a credential was rejected.
pub(crate) fn bearer_outcome(parts: &axum::http::request::Parts) -> BearerOutcome {
    parts
        .extensions
        .get::<BearerOutcome>()
        .copied()
        .unwrap_or_default()
}

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

/// MAPPS-491 (MAPPS-474 phase 2): fill `identity_id`,
/// `active_membership_id`, and `memberships` on an authenticated
/// `AuthState`. Safe no-op when the state is unauthenticated or the
/// tenant is missing. `mid_hint` comes from the JWT (`JwtClaims.mid`);
/// when absent, the membership id is resolved from
/// `(email, tenant_id)`. Runs on the migrator pool because both
/// identity-plane tables are RLS-exempt.
async fn enrich_auth_state_with_identity(
    auth_service: &AuthService,
    state: AuthState,
    mid_hint: Option<uuid::Uuid>,
) -> AuthState {
    let (Some(user), Some(tenant_id)) = (state.user.as_ref(), state.tenant_id) else {
        return state;
    };
    let pool = auth_service.db().migrator_pool();
    let identity_id = crate::db::identity::IdentityRepo::find_id_by_email(pool, &user.email)
        .await
        .ok()
        .flatten();
    let active_membership_id = match mid_hint {
        Some(mid) => Some(mid),
        None => crate::db::identity::MembershipRepo::find_id_by_email_and_tenant(
            pool,
            &user.email,
            tenant_id,
        )
        .await
        .ok()
        .flatten(),
    };
    let memberships = match identity_id {
        Some(id) => {
            crate::db::identity::MembershipRepo::list_views_for_identity(pool, id, Some(tenant_id))
                .await
                .unwrap_or_default()
        }
        None => Vec::new(),
    };
    AuthState {
        identity_id,
        active_membership_id,
        memberships,
        ..state
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
    //
    // MAPPS-348: track the JWT-verified `sub` from whichever path decodes
    // it. If NEITHER path establishes an auth state (both lookups failed),
    // we probe `is_user_tombstoned(sub)` below - a positive result upgrades
    // the plain "no user" default to `AuthState::deleted()`, which the
    // `RequireAuth` extractor turns into a 410 Gone (`ACCOUNT_DELETED`)
    // instead of the generic 401. Distinguishes "your bunyip account was
    // deleted" from "your session expired / please refresh" at the SPA.
    let mut candidate_sub: Option<uuid::Uuid> = None;
    // MAPPS-491: hint the enrich pass with `mid` from the legacy JWT when
    // present. Bunyip tokens never carry it (bunyip does not know about
    // memberships) so the hint stays None on that path and the enrich
    // pass falls back to an (email, tenant_id) lookup.
    let mut mid_hint: Option<uuid::Uuid> = None;
    // Captures a "principal was definitively rejected" AppError (suspended
    // tenant, deactivated user) from either the bunyip path or the legacy
    // path. When set AND no auth path succeeded, short-circuit with the
    // AppError's own response after the block, so the SPA sees the real
    // 403 + copy instead of a generic 401 the AuthGuard reads as
    // "session expired" and loops on.
    let mut principal_rejection: Option<AppError> = None;
    // PMS-769: which bearer outcome the extractors should challenge on.
    let mut outcome = BearerOutcome::Absent;
    let auth_state = match bearer(&request) {
        Some(token) => {
            // A credential was presented; assume it is rejected until a path
            // accepts it (settled after both branches have run).
            outcome = BearerOutcome::Rejected;
            // 1. Bunyip-as-OP Resource-Server path (new). Tokens minted by
            //    bunyip-api carry typ=at+jwt + iss=bunyip's OIDC_ISSUER.
            let from_bunyip = match auth_middleware.bunyip.as_ref() {
                Some(v) => match v.verify_at_jwt(token).await {
                    Ok(claims) => {
                        candidate_sub = uuid::Uuid::parse_str(&claims.sub).ok();
                        let (state, rejection) = ensure_user_from_bunyip(
                            &auth_middleware.auth_service,
                            auth_middleware.tenants.as_ref(),
                            auth_middleware.invitations.as_ref(),
                            v.as_ref(),
                            token,
                            &claims,
                        )
                        .await;
                        if principal_rejection.is_none() {
                            principal_rejection = rejection;
                        }
                        state
                    }
                    // PMS-769: this error used to be dropped on the floor, so
                    // an expired token, a wrong-audience token, a forged
                    // signature and a JWKS outage were indistinguishable in
                    // the log (they all ended as a bare 401). Control flow is
                    // unchanged - `None` still falls through to the legacy
                    // branch below - but the cause is now recorded. A routine
                    // expiry stays at `debug` so a junk-token spray cannot
                    // flood the warn stream; everything else is `warn`,
                    // because a misconfiguration or a JWKS outage must be
                    // loud.
                    Err(e) => {
                        outcome = BearerOutcome::from_verify_error(&e);
                        if outcome == BearerOutcome::Expired {
                            tracing::debug!(error = %e, "bunyip bearer rejected");
                        } else {
                            tracing::warn!(error = %e, "bunyip bearer rejected");
                        }
                        None
                    }
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
                //
                // MAPPS-337: the legacy fallback previously authenticated a
                // user as long as the JWT decoded and the row existed,
                // ignoring `users.status` and the tenant's active state.
                // A deactivated user or a suspended tenant kept working
                // until token TTL. `ensure_user_and_tenant_active` mirrors
                // the checks `login()` runs at login time so revocations
                // take effect on the very next request. PMS-698: those
                // status/tenant checks now live in the shared
                // `ensure_principal_usable`, which the bunyip branch above
                // runs too, so both paths reject the same principal.
                match auth_middleware.auth_service.decode_token(token) {
                    Ok(claims) if claims.typ == "access" => {
                        if candidate_sub.is_none() {
                            candidate_sub = Some(claims.sub);
                        }
                        // MAPPS-491: pull `mid` off the JWT for the enrich
                        // pass below. `None` (legacy token) triggers the
                        // fallback lookup by (email, tenant_id).
                        mid_hint = claims.mid;
                        match auth_middleware
                            .auth_service
                            .ensure_user_and_tenant_active(
                                claims.tid, claims.sub, claims.iat, claims.sid,
                            )
                            .await
                        {
                            // PMS-681: ensure_user_and_tenant_active returns the
                            // user it already loaded, so there is no second query.
                            Ok(user) => {
                                AuthState::authenticated(user.to_current_user(), claims.tid)
                            }
                            // PMS-769: the cause (deactivated user, suspended
                            // tenant, post-password-change `iat`, MAPPS-531
                            // signed-out session) is logged rather than
                            // discarded, so a support report of "it just 401s"
                            // has server-side evidence. `debug`, not `warn`:
                            // every one of these is an expected revocation,
                            // and the 401 itself is the loud part. The reason
                            // is ALSO captured so the outer function can
                            // return the AppError's own response (e.g. 403
                            // "This organization is not active") instead of
                            // dropping to a generic 401 the SPA reads as
                            // "session expired" and loops on.
                            Err(e) => {
                                tracing::debug!(error = %e, user = %claims.sub, "legacy bearer principal rejected");
                                if principal_rejection.is_none() {
                                    principal_rejection = Some(e);
                                }
                                AuthState::default()
                            }
                        }
                    }
                    // A decoded token with the wrong `typ` (e.g. a refresh
                    // token used as a Bearer).
                    Ok(claims) => {
                        tracing::debug!(typ = %claims.typ, "legacy bearer is not an access token");
                        AuthState::default()
                    }
                    // Suppressed deliberately: `decode_token`'s error is
                    // already logged with its cause by
                    // `From<jsonwebtoken::errors::Error> for AppError`, and
                    // every bunyip at+jwt reaching this fallback trips it, so
                    // re-logging here would only double the line.
                    Err(_) => AuthState::default(),
                }
            }
        }
        None => AuthState::default(),
    };

    // MAPPS-348: neither path established an authenticated user, but if we
    // decoded a JWT and its `sub` points at a tombstoned users row, upgrade
    // the state to `deleted` so the extractor returns 410 rather than 401.
    // Probe only on the error branch and only when a sub was successfully
    // decoded - a missing or unparseable token skips the extra query. The
    // probe is unscoped (bypasses the tenant GUC) so it works for both auth
    // paths and for tenant-mismatched tokens.
    let auth_state = if !auth_state.is_authenticated {
        if let Some(sub) = candidate_sub {
            match auth_middleware.auth_service.is_user_tombstoned(sub).await {
                Ok(true) => AuthState::deleted(),
                _ => auth_state,
            }
        } else {
            auth_state
        }
    } else {
        auth_state
    };

    // When neither auth path succeeded AND we captured a definitive principal
    // rejection (suspended tenant, deactivated user - PMS-698 semantics), return
    // the AppError's own response NOW instead of running the request through
    // `next` with an empty AuthState (which downstream extractors turn into a
    // generic 401 the SPA reads as "session expired" and prompts the user to
    // sign in again). The MAPPS-348 tombstone upgrade above takes precedence
    // over principal_rejection - a deleted-account 410 is more specific than a
    // suspended-tenant 403.
    if !auth_state.is_authenticated && !auth_state.deleted {
        if let Some(err) = principal_rejection {
            return err.into_response();
        }
    }

    // MAPPS-491 (MAPPS-474 phase 2): backfill identity + membership fields
    // on the authenticated state so extractors and `GET /auth/memberships`
    // can read them without a second round-trip. No-op when unauthenticated.
    let auth_state =
        enrich_auth_state_with_identity(&auth_middleware.auth_service, auth_state, mid_hint).await;

    // Insert auth state into request extensions
    if auth_state.is_authenticated {
        outcome = BearerOutcome::Accepted;
    }
    request.extensions_mut().insert(auth_state);
    request.extensions_mut().insert(outcome);

    next.run(request).await
}

fn bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// MAPPS-348: shared "resolve the current user or map to the right auth
/// error" used by every extractor below. Ordering matters: an
/// `AuthState::deleted()` (JWT verified, row tombstoned) has to short-
/// circuit BEFORE the generic 401 path, so the SPA sees 410 Gone
/// (`ACCOUNT_DELETED`) and can render the terminal modal instead of
/// falling into its 401-refresh-and-retry loop.
///
/// PMS-769: when the request does end at a 401, `outcome` decides both the
/// error code (`TOKEN_EXPIRED` for a presented-but-expired bearer, else
/// `UNAUTHORIZED`) and the RFC 6750 challenge attached to the response.
fn user_or_auth_error(
    auth_state: &AuthState,
    outcome: BearerOutcome,
) -> Result<CurrentUser, AuthRejection> {
    if auth_state.deleted {
        // 410 Gone, and no challenge: the credential itself verified fine.
        return Err(AppError::AccountDeleted.into());
    }
    match auth_state.user.clone() {
        Some(user) => Ok(user),
        None if outcome == BearerOutcome::Expired => {
            Err(AuthRejection::challenged(AppError::TokenExpired, outcome))
        }
        None => Err(AuthRejection::challenged(AppError::Unauthorized, outcome)),
    }
}

/// Extractor for requiring authentication
#[derive(Clone)]
pub struct RequireAuth(pub CurrentUser);

impl<S> axum::extract::FromRequestParts<S> for RequireAuth
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .cloned()
            .unwrap_or_default();

        Ok(RequireAuth(user_or_auth_error(
            &auth_state,
            bearer_outcome(parts),
        )?))
    }
}

/// MAPPS-491 (MAPPS-474 phase 2): extractor that surfaces the FULL
/// authenticated `AuthState` (identity_id, active_membership_id,
/// memberships, plus the user + tenant). Handlers that need the
/// membership set — currently `GET /auth/memberships` — reach for this
/// instead of `RequireAuth`, which only exposes `CurrentUser`.
#[derive(Clone)]
pub struct RequireAuthState(pub AuthState);

impl<S> axum::extract::FromRequestParts<S> for RequireAuthState
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
        // Reuse the RequireAuth gate: if the state isn't authenticated
        // (or is tombstoned), map to the same 401 / 410.
        user_or_auth_error(&auth_state, bearer_outcome(parts))?;
        Ok(RequireAuthState(auth_state))
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
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .cloned()
            .unwrap_or_default();

        let user = user_or_auth_error(&auth_state, bearer_outcome(parts))?;
        Ok(TenantScope {
            tenant_id: super::tenant::TenantScoped::tenant(&user),
            user,
        })
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
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .cloned()
            .unwrap_or_default();

        let user = user_or_auth_error(&auth_state, bearer_outcome(parts))?;
        let user_role = user.role.as_str();
        if R::allowed_roles().contains(&user_role) {
            Ok(RequireRole(user, std::marker::PhantomData))
        } else {
            Err(AppError::Forbidden("You do not have permission to do that".to_string()).into())
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
    type Rejection = AuthRejection;

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
    /// Human noun for the 404 message. `NAME` is the `module_config` key
    /// (`rmm_integration`), which must not reach a user (PMS-775).
    const LABEL: &'static str;
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
/// `knowledge_base`, `rmm_integration`, `reports`, `time_tracking`,
/// `timesheets`.
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
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // First require authentication; share the same AuthState path
        // as RequireAuth so misconfigured handlers fail-closed on auth
        // before ever touching the gate. MAPPS-348: `user_or_auth_error`
        // maps a tombstoned row to 410 Gone before falling to 401.
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .cloned()
            .unwrap_or_default();
        let user = user_or_auth_error(&auth_state, bearer_outcome(parts))?;

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
            return Err(AppError::NotFound(format!("{} module", G::LABEL)).into());
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
    ($struct_name:ident, $module_name:expr, $label:expr, $alias:ident) => {
        pub struct $struct_name;
        impl ModuleGate for $struct_name {
            const NAME: &'static str = $module_name;
            const LABEL: &'static str = $label;
        }
        pub type $alias = RequireModuleEnabled<$struct_name>;
    };
}

gated_module!(BillingModule, "billing", "Billing", RequireBilling);
gated_module!(ProjectsModule, "projects", "Projects", RequireProjects);
gated_module!(CalendarModule, "calendar", "Calendar", RequireCalendar);
gated_module!(ContractsModule, "contracts", "Contracts", RequireContracts);
gated_module!(AssetsModule, "assets", "Assets", RequireAssets);
gated_module!(
    KnowledgeBaseModule,
    "knowledge_base",
    "Knowledge base",
    RequireKnowledgeBase
);
gated_module!(RmmModule, "rmm_integration", "RMM integration", RequireRmm);
gated_module!(ReportsModule, "reports", "Reports", RequireReports);
gated_module!(
    TimeTrackingModule,
    "time_tracking",
    "Time tracking",
    RequireTimeTracking
);
// PMS-943: timesheets are separate from `time_tracking` on purpose. Logging
// time is not the same feature as submitting a week of it for approval: a
// one-person MSP still logs and still bills, it just has nobody to submit to.
// The timesheet routes carry BOTH gates, so turning time tracking off still
// takes the timesheets with it.
gated_module!(
    TimesheetsModule,
    "timesheets",
    "Timesheets",
    RequireTimesheets
);

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
/// Returns `None` when the user can't be resolved AND can't be created, or
/// when the resolved principal fails `AuthService::ensure_principal_usable`
/// (inactive user / non-active tenant, PMS-698). The caller treats `None` as
/// "drop the bunyip path" and falls back to legacy.
async fn ensure_user_from_bunyip(
    auth_service: &Arc<AuthService>,
    tenants: Option<&Arc<crate::modules::tenants::TenantService>>,
    invitations: Option<&Arc<crate::modules::invitations::InvitationsService>>,
    verifier: &BunyipVerifier,
    bearer: &str,
    claims: &super::oidc_rs::AtClaims,
) -> (Option<AuthState>, Option<AppError>) {
    let Some(sub) = uuid::Uuid::parse_str(&claims.sub).ok() else {
        return (None, None);
    };

    // PMS-244: orgs live in Mokosh (Bunyip is a personal-subscription IdP with
    // no org concept), so the tenant is resolved from Mokosh's own membership
    // state, NOT a token claim. Priority: a pending invite for the user's
    // verified email wins; else their existing placement; else a brand-new user
    // gets their own `personal` tenant (self-signup). Email/name come from
    // /oauth2/userinfo (the at+jwt carries no email claim).
    //
    // PMS-713: `/oauth2/userinfo` is a network round-trip to Bunyip, and this
    // path runs on EVERY authenticated request. Fetching it unconditionally made
    // each request wait on Bunyip; the dashboard fires several API calls on
    // refresh, so the round-trips compounded into a multi-second, main-thread-idle
    // stall that looked like a Dioxus render freeze but is pure I/O wait. userinfo
    // is only needed to JIT-provision a first-sight user, back-fill a user stuck
    // in the legacy default tenant, or match a pending invite (all keyed on the
    // IdP email/name). An already-provisioned, already-placed user with no pending
    // invite needs none of it: `place_bunyip_user` resolves them from local state
    // with `None` email/name, still running the PMS-698 principal gate and the
    // role reconcile. Skip the hop for that (overwhelmingly common) case.
    //
    // PMS-777: the decision below is made from local state, and that state is
    // exactly what `place_bunyip_user` needs next. Carry it across instead of
    // re-reading it (the skip path used to read `users` twice and
    // `tenant_invitations` once, then throw all three results away).
    let (email, email_verified, given_name, family_name) =
        match place_bunyip_user_from_local_state(auth_service, tenants, invitations, sub, claims)
            .await
        {
            LocalPlacement::Placed(state) => return (*state, None),
            LocalPlacement::UserinfoNeeded => {
                let info = verifier.userinfo(bearer).await;
                // MAPPS-335: bind the userinfo response to the verified at+jwt by
                // asserting `info.sub == claims.sub` before reading any other field.
                // Without this guard a misbehaving / compromised /oauth2/userinfo
                // response (load-balancing bug at the OP, attacker-influenced
                // response, etc.) injects ANOTHER user's `email` / `email_verified` /
                // `given_name` / `family_name` into the JIT row keyed on `claims.sub`.
                // The at+jwt's signature is already validated; sub is the canonical
                // join key. Drop the userinfo response (treat as unverified email + no
                // name hints) on mismatch so we never JIT a wrong-identity row, but
                // keep the request alive so a transient OP glitch does not 401 the
                // user across the whole site.
                let info = info.filter(|i| {
                    if i.sub == claims.sub {
                        true
                    } else {
                        tracing::warn!(
                            claims_sub = %claims.sub,
                            userinfo_sub = %i.sub,
                            "userinfo sub does not match at+jwt sub; dropping userinfo claims"
                        );
                        false
                    }
                });
                let email = info.as_ref().and_then(|i| i.email.clone());
                let email_verified = info
                    .as_ref()
                    .and_then(|i| i.email_verified)
                    .unwrap_or(false);
                // BUNYIP-141: standard profile claims off the same userinfo round-trip.
                // Bunyip emits them only when the at+jwt's scope set covers `profile`
                // AND the bunyip-side column is non-NULL (BUNYIP-140); absent here
                // means either "scope not requested" or "user has not filled it in",
                // in both cases the JIT path falls back to `synthetic_name_from_email`.
                let given_name = info.as_ref().and_then(|i| i.given_name.clone());
                let family_name = info.as_ref().and_then(|i| i.family_name.clone());
                // Nothing is carried across on this branch: the userinfo
                // response can change the placement answer, so the full path
                // re-resolves from scratch exactly as it always did.
                (email, email_verified, given_name, family_name)
            }
        };

    place_bunyip_user_with_rejection(
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

/// PMS-777: how far [`place_bunyip_user_from_local_state`] got.
pub enum LocalPlacement {
    /// Local state was enough: the caller is placed (or rejected by the
    /// PMS-698 principal gate) with no `/oauth2/userinfo` hop. Boxed so the
    /// `AuthState` (which carries a whole `CurrentUser`) does not set the size
    /// of the empty `UserinfoNeeded` variant.
    Placed(Box<Option<AuthState>>),
    /// Local state was not enough - a first-sight user, a user stuck in the
    /// legacy default tenant, a placeholder email, or a waiting invite - so the
    /// caller must fetch `/oauth2/userinfo` and run the full path.
    UserinfoNeeded,
}

/// PMS-777: the whole userinfo-free request path, in two statements.
///
/// `resolve_bunyip_caller` reads the caller's `users` row and the waiting-invite
/// flag in one statement, and hands that row straight to `place_bunyip_caller`,
/// which used to re-read both. The only other statement left is the PMS-698
/// principal gate's tenant-status check, which is security-relevant and
/// deliberately still runs on every request.
///
/// Public because it is the branch production takes for an already-provisioned
/// caller, and the query-budget regression test
/// (`tests/bunyip_query_budget.rs`) asserts its cost directly.
pub async fn place_bunyip_user_from_local_state(
    auth_service: &Arc<AuthService>,
    tenants: Option<&Arc<crate::modules::tenants::TenantService>>,
    invitations: Option<&Arc<crate::modules::invitations::InvitationsService>>,
    sub: uuid::Uuid,
    claims: &super::oidc_rs::AtClaims,
) -> LocalPlacement {
    let principal = match resolve_bunyip_caller(auth_service, invitations, sub).await {
        UserinfoDecision::Needed => return LocalPlacement::UserinfoNeeded,
        UserinfoDecision::Skip(principal) => *principal,
    };
    LocalPlacement::Placed(Box::new(
        place_bunyip_caller(
            auth_service,
            tenants,
            invitations,
            sub,
            // No userinfo, so no email / name hints: the placement, the
            // placeholder repair and the name refresh all no-op, and the row
            // comes from `principal`.
            None,
            false,
            None,
            None,
            claims,
            Some(principal),
        )
        .await
        .0,
    ))
}

/// PMS-777: what `resolve_bunyip_caller` decided, and the state it read to
/// decide it. `Skip` carries the caller forward so `place_bunyip_caller` does
/// not read the same rows again.
enum UserinfoDecision {
    Needed,
    // Boxed: the principal carries a whole `User`, and `Needed` (the rarer but
    // still routine variant) would otherwise pay for it on every request.
    Skip(Box<BunyipPrincipal>),
}

/// Whether the Bunyip RS path must fetch `/oauth2/userinfo` for this request
/// (PMS-713). userinfo is a per-request network hop to Bunyip; it is only needed
/// to JIT-provision a first-sight user, back-fill a user stuck in the legacy
/// default tenant, or match a pending invite - all of which key on the IdP
/// email/name. An already-provisioned user placed in a real tenant with no
/// pending invite needs none of it and is resolved from local state, so the hop
/// is skipped for that (overwhelmingly common) case. PMS-777: every check runs
/// off one local `users` read - cheap next to the round-trip it avoids.
pub async fn bunyip_userinfo_needed(
    auth_service: &Arc<AuthService>,
    invitations: Option<&Arc<crate::modules::invitations::InvitationsService>>,
    sub: uuid::Uuid,
) -> bool {
    matches!(
        resolve_bunyip_caller(auth_service, invitations, sub).await,
        UserinfoDecision::Needed
    )
}

/// The decision above, plus the state it was made from (PMS-777).
///
/// One statement, one pool checkout: [`AuthService::find_bunyip_principal`]
/// reads the caller's `users` row and the "is an invite waiting" flag together.
/// Everything after that is a pure function of that row, so a `Skip` hands the
/// row straight to [`place_bunyip_caller`] rather than making it re-read.
async fn resolve_bunyip_caller(
    auth_service: &Arc<AuthService>,
    invitations: Option<&Arc<crate::modules::invitations::InvitationsService>>,
    sub: uuid::Uuid,
) -> UserinfoDecision {
    // First sight: no local row yet, so the user must be JIT-provisioned (needs
    // email + name from userinfo). A read error reads the same way it did when
    // this was `find_user_placement(..).ok().flatten()`: no placement, so the
    // full path runs and re-reads.
    let principal = match auth_service.find_bunyip_principal(sub).await {
        Ok(Some(principal)) => principal,
        Ok(None) => return UserinfoDecision::Needed,
        Err(e) => {
            tracing::warn!(error = %e, sub = %sub, "bunyip principal lookup failed");
            return UserinfoDecision::Needed;
        }
    };
    let (tenant, role) = &principal.placement;
    // Stuck in the legacy default tenant: PMS-245 re-homes them to their own
    // personal tenant via the full placement path.
    if is_stuck_in_default(Some(*tenant), default_bunyip_tenant_id(), role, false) {
        return UserinfoDecision::Needed;
    }
    // PMS-635: the row still carries the `{sub}@unresolved.invalid` JIT
    // placeholder, so it holds no usable address (every mokosh email to it
    // bounces) and no invite can ever match it. Only userinfo can tell us
    // whether bunyip has since verified the address, so keep fetching it until
    // the row is repaired. This costs the PMS-713 hop for as long as the user
    // stays unverified, which is a bounded, self-clearing state.
    if is_unresolved_placeholder_email(&principal.user.email) {
        return UserinfoDecision::Needed;
    }
    // A pending invite for the user's verified email re-homes them, so the full
    // path must run. Match on the user's LOCAL verified email (no userinfo): a
    // JIT row carries a verified email only when the IdP reported it verified,
    // which is exactly the condition the invite-consumption path already requires
    // (place_bunyip_user gates the invite match on `email_verified`).
    // `has_pending_invite` already encodes the `email_verified_at IS NOT NULL`
    // half of that gate. The `invitations` check stays because a wiring without
    // the service handles no invites at all, and must not start now.
    if invitations.is_some() && principal.has_pending_invite {
        return UserinfoDecision::Needed;
    }
    UserinfoDecision::Skip(Box::new(principal))
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
/// Backward-compatible wrapper: discards any principal-rejection reason and
/// returns only the resolved `AuthState`. The bunyip_login integration test
/// suite calls this directly and does not need the rejection detail.
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
    place_bunyip_user_with_rejection(
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
    .0
}

/// Variant that returns both the resolved `AuthState` AND any principal
/// rejection reason (deactivated user / suspended tenant). The middleware
/// uses this so it can short-circuit the request with the AppError's own
/// 403 response instead of dropping to a generic 401 the SPA reads as
/// "session expired" and loops on.
#[allow(clippy::too_many_arguments)]
pub async fn place_bunyip_user_with_rejection(
    auth_service: &Arc<AuthService>,
    tenants: Option<&Arc<crate::modules::tenants::TenantService>>,
    invitations: Option<&Arc<crate::modules::invitations::InvitationsService>>,
    sub: uuid::Uuid,
    email: Option<String>,
    email_verified: bool,
    given_name: Option<String>,
    family_name: Option<String>,
    claims: &super::oidc_rs::AtClaims,
) -> (Option<AuthState>, Option<AppError>) {
    place_bunyip_caller(
        auth_service,
        tenants,
        invitations,
        sub,
        email,
        email_verified,
        given_name,
        family_name,
        claims,
        None,
    )
    .await
}

/// [`place_bunyip_user`] with the PMS-777 fast path: `resolved` is the caller
/// `resolve_bunyip_caller` already read this request. When it is `Some` and
/// the user turns out to stay in the tenant they are already in, the placement
/// and the user row are taken from it instead of being read again. `None`
/// (every test call site, and the userinfo branch) resolves from the database
/// exactly as before.
#[allow(clippy::too_many_arguments)]
async fn place_bunyip_caller(
    auth_service: &Arc<AuthService>,
    tenants: Option<&Arc<crate::modules::tenants::TenantService>>,
    invitations: Option<&Arc<crate::modules::invitations::InvitationsService>>,
    sub: uuid::Uuid,
    email: Option<String>,
    email_verified: bool,
    given_name: Option<String>,
    family_name: Option<String>,
    claims: &super::oidc_rs::AtClaims,
    resolved: Option<BunyipPrincipal>,
) -> (Option<AuthState>, Option<AppError>) {
    let placement = match resolved.as_ref() {
        Some(principal) => Some(principal.placement.clone()),
        None => auth_service.find_user_placement(sub).await.ok().flatten(),
    };
    // `current` is recomputed below after the TEMPORARY MAPPS-458
    // email-fallback may have widened `placement`; do not shadow here.

    // An invite to address X is consumed only by a Bunyip user with verified X.
    let invite = match (invitations, email.as_deref()) {
        (Some(invs), Some(em)) if email_verified => {
            invs.newest_pending_for(em).await.ok().flatten()
        }
        _ => None,
    };

    // MAPPS-458 (PMS-728 slice 2): Bunyip is no longer an onboarding
    // surface. A `sub` that has no existing `users` row AND no pending
    // invitation for the presented email is rejected here; the request
    // returns 401 upstream when `place_bunyip_user` yields `None`.
    // Users arrive via the explicit invitations flow, not silent JIT
    // creation. `placement.is_some()` covers every already-provisioned
    // user (including the stuck-in-default backfill, which is a tenant
    // rehome, not a fresh user creation).
    //
    // Carve-out for the platform admin (`bunyip_role = "admin"`): this
    // is the root/owner of the Mokosh instance in the bunyip model
    // (PMS-728 proposed approach: "the root/owner user keeps a
    // Bunyip-backed login"). They bootstrap the first tenant, so they
    // must be able to sign in on a fresh instance without a
    // pre-existing invitation - matches the `bootstrap_admin_*`
    // regression pins in `tests/bunyip_login.rs`.
    let is_platform_admin = claims.bunyip_role.as_deref() == Some("admin");

    // TEMPORARY (mokosh-contact-login staging bypass): the c-01 dev DB
    // has drifted from bunyip's `sub` for every tenant admin (a bunyip
    // instance reset without a mokosh-side rekey), so
    // `find_user_placement(sub)` returns None even for accounts that
    // have valid `users` rows under their email. Every non-platform-
    // admin user 401s at MAPPS-458 as a result.
    //
    // Before rejecting, try to resolve placement by verified email. If
    // a users row exists there, accept the request and REBIND `sub` to
    // that row's id so the downstream `get_user_by_id(target, sub)`
    // (line ~1290), `rehome_user_between_tenants`, and every other
    // helper that keys on `sub` address the real mokosh users row.
    // `users.id` is not rewritten - the 55 FKs to `users(id)` are not
    // ON UPDATE CASCADE and rewriting the id would leave every one of
    // them dangling. The row's id stays what it is; we just stop using
    // the mismatched bunyip sub for this request.
    //
    // Remove this block on merge back to main - the production model
    // is "invitations, not silent JIT" (MAPPS-458 / PMS-728 slice 2).
    let (placement, sub) = match (placement, email.as_deref()) {
        (Some(p), _) => (Some(p), sub),
        // TEMPORARY: `email_verified` is deliberately NOT required here,
        // because some bunyip configs on staging emit the claim as `false`
        // (or omit it entirely) even for real user rows. Production
        // MAPPS-458 is untouched; this fallback lives only on this branch.
        (None, Some(em)) => {
            tracing::warn!(
                bunyip_sub = %sub,
                email = %em,
                email_verified = email_verified,
                "TEMPORARY MAPPS-458 bypass: placement lookup by sub returned None; attempting by-email lookup"
            );
            match auth_service.find_user_placement_by_email(em).await {
                Ok(Some((users_id, tenant, role))) => {
                    tracing::warn!(
                        bunyip_sub = %sub,
                        users_id = %users_id,
                        email = %em,
                        tenant_id = %tenant,
                        role = %role,
                        "TEMPORARY MAPPS-458 bypass: matched users row by email; rebinding sub to that row's id and accepting"
                    );
                    (Some((tenant, role)), users_id)
                }
                Ok(None) => {
                    tracing::warn!(
                        bunyip_sub = %sub,
                        email = %em,
                        "TEMPORARY MAPPS-458 bypass: by-email lookup found no matching users row; will fall through to MAPPS-458"
                    );
                    (None, sub)
                }
                Err(e) => {
                    tracing::warn!(error = %e, sub = %sub, "find_user_placement_by_email failed; falling through to MAPPS-458");
                    (None, sub)
                }
            }
        }
        (None, None) => {
            tracing::warn!(
                bunyip_sub = %sub,
                "TEMPORARY MAPPS-458 bypass: no email in the JWT, cannot attempt by-email lookup"
            );
            (None, sub)
        }
    };
    let current = placement.as_ref().map(|(t, _)| *t);

    if placement.is_none() && invite.is_none() && !is_platform_admin {
        tracing::info!(
            sub = %sub,
            email = email.as_deref().unwrap_or("<absent>"),
            "bunyip-authenticated identity has no local placement and no pending invitation; rejecting per MAPPS-458"
        );
        return (None, None);
    }

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
            Some(svc) => match svc
                .ensure_personal_tenant(sub, given_name.as_deref(), email.as_deref())
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, sub = %sub, "personal tenant provisioning failed");
                    return (None, None);
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
    // PMS-777: the pre-resolved row is only usable when the user did not move
    // (no invite, no backfill); a re-home means the row must be re-read from
    // the tenant it landed in.
    let already_loaded = resolved
        .map(|principal| principal.user)
        .filter(|user| user.tenant_id == target);
    let mut user = match already_loaded {
        Some(user) => user,
        None => match auth_service.get_user_by_id(target, sub).await {
            Ok(user) => user,
            Err(_) => {
                // Persist the IdP-supplied email on the JIT insert ONLY when
                // the IdP reports it verified.
                // `upsert_user_from_oidc` (MAPPS-335) now binds
                // `email_verified_at` to the actual `email_verified` flag, so
                // an unverified address lands with NULL instead of NOW();
                // writing the placeholder under `sub@unresolved.invalid` keeps
                // the auto-link/capture path against the real owner closed.
                let email_for_insert = match (email.clone(), email_verified) {
                    (Some(em), true) => em,
                    _ => format!("{sub}@{UNRESOLVED_EMAIL_DOMAIN}"),
                };
                // BUNYIP-141: hand the userinfo profile claims to the JIT path
                // so a bunyip-provisioned user lands with their real name on
                // first sight. Both are Option<String>; None falls back to
                // `synthetic_name_from_email` inside the service.
                match auth_service
                    .upsert_user_from_oidc(
                        sub,
                        target,
                        &email_for_insert,
                        initial_role,
                        given_name.as_deref(),
                        family_name.as_deref(),
                        email_verified,
                    )
                    .await
                {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::warn!(error = %e, sub = %sub, "JIT user upsert failed");
                        return (None, None);
                    }
                }
            }
        },
    };

    // PMS-635: heal a row still holding the `{sub}@unresolved.invalid`
    // placeholder now that bunyip reports a verified address. The JIT insert
    // runs once, so without this the placeholder was permanent: transactional
    // mail (login-approval codes, notifications) was addressed to a reserved
    // non-routable domain and bounced, and `email_verified_at` stayed NULL so
    // invites never matched. Only ever overwrites the placeholder, never a real
    // address; a failure is logged and the request continues (the next request
    // retries).
    if let (Some(em), true) = (email.as_deref(), email_verified) {
        if is_unresolved_placeholder_email(&user.email) {
            match auth_service
                .repair_placeholder_email(user.tenant_id, user.id, em)
                .await
            {
                Ok(repaired) => {
                    tracing::info!(sub = %sub, "repaired placeholder email from verified userinfo");
                    user = repaired;
                }
                Err(e) => {
                    tracing::warn!(error = %e, sub = %sub, "placeholder email repair failed")
                }
            }
        }
    }

    // PMS-512: bunyip owns the profile names, so the local columns are a
    // read-only cache refreshed from every login's userinfo claims (the JIT
    // branch above already seeded them, so only the existing-row branch can
    // drift). This helper runs per request, not per login, so only write when
    // a non-empty hint actually differs; an absent or empty hint leaves the
    // NOT NULL column untouched.
    let first_hint = given_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let last_hint = family_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let names_drifted = first_hint.is_some_and(|f| f != user.first_name)
        || last_hint.is_some_and(|l| l != user.last_name);
    if names_drifted {
        match auth_service
            .refresh_names_from_oidc(user.tenant_id, user.id, first_hint, last_hint)
            .await
        {
            Ok(refreshed) => user = refreshed,
            // PMS-787: best-effort cosmetic name sync. A failure leaves the
            // request unaffected (the user keeps its stored name), and a real DB
            // fault surfaces loudly on the login's own queries, so this is a
            // debug diagnostic rather than a warn on every successful login.
            Err(e) => tracing::debug!(error = %e, sub = %sub, "profile name refresh failed"),
        }
    }

    // PMS-698: same principal gate the legacy HS256 branch runs, so a
    // deactivated user or a suspended tenant loses access on the very next
    // request on this path too. `None` drops the bunyip path; the legacy
    // fallback cannot decode a bunyip token, so the request ends unauthenticated
    // and the extractors answer 401/403 instead of silently authenticating.
    // Excludes the PMS-681 `iat`-vs-`password_changed_at` cutoff on purpose:
    // bunyip owns the credential here, so a mokosh-side password change is not
    // a revocation signal for a bunyip token.
    if let Err(e) = auth_service.ensure_principal_usable(&user).await {
        tracing::info!(error = %e, user = %user.id, tenant_id = %user.tenant_id, "rejecting bunyip principal");
        // Propagate the rejection so the middleware can short-circuit with the
        // AppError's 403 "This organization is not active" response instead of
        // falling through to legacy + landing on a generic 401 the SPA reads
        // as "session expired" and loops on.
        return (None, Some(e));
    }

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
    // MAPPS-330: every Mokosh user is an admin of their own instance. The
    // PMS-458 invite-respect branch (preserving least-privilege grants into
    // SHARED org tenants) is removed: even invited joiners floor at `admin`,
    // and a platform-level Bunyip `admin` claim still rises to `super_admin`.
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
    (
        Some(AuthState::authenticated(user.to_current_user(), tenant_id)),
        None,
    )
}

/// Translate Bunyip's system role (the `bunyip_role` claim) into mokosh's
/// effective role on the Bunyip RS path (PMS-172, revised for the
/// single-tenancy posture in PMS-447 and again for the MAPPS-513 /
/// MAPPS-518 auth-plane split).
///
/// After PMS-447 each Mokosh tenant has exactly one user (the owner), so a
/// signed-in Bunyip user IS the admin of their own world by construction.
///
/// MAPPS-519 (MAPPS-518 stage B follow-up): the mokosh platform
/// super-admin persona lives in `platform_admins`, not in a `users` row.
/// Migration 133 deletes every existing `users.role='super_admin'` row,
/// and every previously-`RequireSuperAdmin` handler is now gated on
/// `RequirePlatformAdmin` (a `/platform/login` bearer). This mapping
/// used to promote a bunyip `admin` to `UserRole::SuperAdmin` on the
/// tenant plane, which would silently re-create a super_admin `users`
/// row on the next bunyip JIT — reopening the shared-identity data
/// surface that migration 133 just closed if that bunyip admin shared
/// an email with an existing tenant admin. The mapping now flattens to
/// `Admin`: being a bunyip admin still owns the tenant, but no longer
/// implicitly carries mokosh-platform privilege. Platform-plane
/// privilege comes only from a `platform_admins` row.
///
/// - `admin`      -> mokosh `admin` (single-tenancy floor; owner of the
///   caller's own tenant, nothing more). See the MAPPS-519 note above.
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
        // MAPPS-519: `admin` no longer promotes to `SuperAdmin`.
        // Every branch below returns `UserRole::Admin`; the regression
        // test at the bottom of this module pins that invariant so a
        // future accidental flip fails a unit test rather than
        // silently reopening the identity-share surface.
        Some(_) => {
            // PMS-447: bunyip `admin` / `subscriber` / any unknown role
            // -> tenant admin. A stale local `super_admin` clamps down
            // to `admin`; anything lower than `admin` (Technician,
            // Manager, etc.) upgrades up to `admin`.
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
///
/// MAPPS-518: post stage B the platform super-admin persona lives in
/// `platform_admins`, not `users`, so no `users.role = 'super_admin'`
/// row is produced by any production code path (bootstrap + Google
/// auto-provision both switched away). The check is retained for the
/// integration-test fixtures that still seed a role='super_admin' row
/// in the default tenant (`common::seed_admin`) to keep those tests
/// stable; it is a no-op in production.
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
        default_bunyip_tenant_id, effective_role_from_bunyip, is_stuck_in_default,
        user_or_auth_error, AuthRejection, AuthState, BearerOutcome, CurrentUser, UserRole,
        VerifyError,
    };
    use crate::utils::error::AppError;
    use axum::response::IntoResponse;
    use uuid::Uuid;

    /// Render a rejection and return `(status, WWW-Authenticate, error code)`.
    async fn rendered(rejection: AuthRejection) -> (u16, Option<String>, String) {
        let response = rejection.into_response();
        let status = response.status().as_u16();
        let challenge = response
            .headers()
            .get("www-authenticate")
            .map(|v| v.to_str().expect("ascii challenge").to_string());
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let envelope: serde_json::Value = serde_json::from_slice(&body).expect("json envelope");
        let code = envelope["error"]["code"]
            .as_str()
            .expect("error code")
            .to_string();
        (status, challenge, code)
    }

    fn stub_user() -> CurrentUser {
        CurrentUser {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            email: "test@example.com".into(),
            first_name: "T".into(),
            last_name: "U".into(),
            role: UserRole::Admin,
            timezone: "UTC".into(),
            avatar_url: None,
            profile_completed: true,
            date_format_string: None,
            theme_base_mode: None,
            theme_accent_id: None,
            own_company_id: None,
            tenant_kind: String::new(),
        }
    }

    #[test]
    fn require_auth_returns_account_deleted_when_tombstoned() {
        // MAPPS-348: `AuthState::deleted()` (JWT decoded, row tombstoned) must
        // short-circuit to `AccountDeleted` (410 Gone) instead of falling
        // through to the generic `Unauthorized` (401). Pins the ordering the
        // SPA relies on to distinguish "account gone" from "session expired".
        // PMS-769: still true for an EXPIRED bearer, which now has its own
        // error - the 410 keeps precedence over both TokenExpired and
        // Unauthorized, and carries no bearer challenge.
        let deleted = AuthState::deleted();
        for outcome in [
            BearerOutcome::Absent,
            BearerOutcome::Expired,
            BearerOutcome::Rejected,
        ] {
            match user_or_auth_error(&deleted, outcome) {
                Err(AuthRejection {
                    error: AppError::AccountDeleted,
                    challenge: None,
                }) => {}
                other => panic!("expected unchallenged AccountDeleted, got {other:?}"),
            }
        }
    }

    #[test]
    fn require_auth_returns_unauthorized_when_no_user_and_not_deleted() {
        // Default AuthState (no bearer, malformed token, verified-but-missing
        // sub) keeps the pre-348 behaviour: plain 401.
        let empty = AuthState::default();
        match user_or_auth_error(&empty, BearerOutcome::Absent) {
            Err(AuthRejection {
                error: AppError::Unauthorized,
                ..
            }) => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn require_auth_returns_user_when_authenticated() {
        // Authenticated path is unchanged: the extractor hands back the user
        // and no error path fires.
        let user = stub_user();
        let authed = AuthState::authenticated(user.clone(), Uuid::from_u128(2));
        let got = user_or_auth_error(&authed, BearerOutcome::Accepted).expect("authenticated");
        assert_eq!(got.id, user.id);
    }

    #[test]
    fn only_expired_verification_maps_to_the_expired_outcome() {
        // PMS-769: `VerifyError::Expired` is the one variant that earns
        // `TOKEN_EXPIRED` + the `error_description` challenge; every other
        // cause is a plain `invalid_token`.
        assert_eq!(
            BearerOutcome::from_verify_error(&VerifyError::Expired),
            BearerOutcome::Expired
        );
        for error in [
            VerifyError::Malformed("bad header".into()),
            VerifyError::InvalidSignature,
            VerifyError::UnknownKid,
            VerifyError::InvalidIssuer,
            VerifyError::InvalidAudience,
            VerifyError::JwksFetch("boom".into()),
            VerifyError::DiscoveryFetch("boom".into()),
        ] {
            assert_eq!(
                BearerOutcome::from_verify_error(&error),
                BearerOutcome::Rejected,
                "unexpected outcome for {error}"
            );
        }
    }

    #[tokio::test]
    async fn expired_bearer_yields_token_expired_with_the_rfc6750_challenge() {
        // PMS-769 incident case: the SPA presented a bunyip token 32 hours past
        // `exp`. The response must name the cause instead of collapsing into
        // the same 401 a credential-less request gets.
        let rejection =
            user_or_auth_error(&AuthState::default(), BearerOutcome::Expired).unwrap_err();
        let (status, challenge, code) = rendered(rejection).await;
        assert_eq!(status, 401);
        assert_eq!(code, "TOKEN_EXPIRED");
        assert_eq!(
            challenge.as_deref(),
            Some(r#"Bearer error="invalid_token", error_description="The access token expired""#)
        );
    }

    #[tokio::test]
    async fn missing_credential_yields_the_bare_bearer_challenge() {
        // No `Authorization` header: RFC 6750 section 3 wants the bare scheme
        // challenge, and no `error` parameter (nothing was rejected).
        let rejection =
            user_or_auth_error(&AuthState::default(), BearerOutcome::Absent).unwrap_err();
        let (status, challenge, code) = rendered(rejection).await;
        assert_eq!(status, 401);
        assert_eq!(code, "UNAUTHORIZED");
        assert_eq!(challenge.as_deref(), Some("Bearer"));
    }

    #[tokio::test]
    async fn rejected_bearer_yields_invalid_token_challenge() {
        // A presented-but-invalid bearer (bad signature, wrong audience,
        // unusable principal) is `invalid_token` without the expiry detail.
        let rejection =
            user_or_auth_error(&AuthState::default(), BearerOutcome::Rejected).unwrap_err();
        let (status, challenge, code) = rendered(rejection).await;
        assert_eq!(status, 401);
        assert_eq!(code, "UNAUTHORIZED");
        assert_eq!(
            challenge.as_deref(),
            Some(r#"Bearer error="invalid_token""#)
        );
    }

    #[tokio::test]
    async fn require_auth_extractor_attaches_the_challenge_end_to_end() {
        // The pieces above are wired through the real `RequireAuth` extractor
        // and axum's response path, so the header survives `IntoResponse` and
        // is not an artefact of the helper.
        use axum::{body::Body, http::Request, routing::get, Router};
        use tower::ServiceExt;

        for (outcome, expected_challenge, expected_code) in [
            (BearerOutcome::Absent, "Bearer", "UNAUTHORIZED"),
            (
                BearerOutcome::Rejected,
                r#"Bearer error="invalid_token""#,
                "UNAUTHORIZED",
            ),
            (
                BearerOutcome::Expired,
                r#"Bearer error="invalid_token", error_description="The access token expired""#,
                "TOKEN_EXPIRED",
            ),
        ] {
            let app = Router::new()
                .route("/", get(|_: super::RequireAuth| async { "ok" }))
                .layer(axum::middleware::from_fn(
                    move |mut request: Request<Body>, next: axum::middleware::Next| async move {
                        request.extensions_mut().insert(outcome);
                        next.run(request).await
                    },
                ));
            let response = app
                .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), 401);
            assert_eq!(
                response.headers().get("www-authenticate").unwrap(),
                expected_challenge
            );
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(envelope["error"]["code"], expected_code);
        }
    }

    #[tokio::test]
    async fn post_authentication_errors_carry_no_challenge() {
        // A 403 from the role gate, the module gate's 404 and the wiring-bug
        // 500 all reach the client through `AuthRejection` too, but none of
        // them concerns a bearer credential, so none gets a challenge.
        for error in [
            AppError::Forbidden("You do not have permission to do that".to_string()),
            AppError::NotFound("module billing".to_string()),
            AppError::Internal("SettingsService extension missing".to_string()),
        ] {
            let (_, challenge, _) = rendered(AuthRejection::from(error)).await;
            assert_eq!(challenge, None);
        }
    }

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
    fn bunyip_admin_maps_to_tenant_admin() {
        // MAPPS-519 (MAPPS-518 stage B follow-up): a Bunyip `admin` used
        // to promote to `UserRole::SuperAdmin`, which - combined with
        // the MAPPS-498 users<->identities mirror - re-created a
        // super_admin `users` row on every bunyip JIT and reopened the
        // shared-identity data surface migration 133 closed. The
        // mapping now flattens to tenant `Admin`: the bunyip admin
        // still owns their tenant (PMS-447 single-tenancy floor), but
        // no longer implicitly carries mokosh-platform privilege.
        // Platform-plane privilege comes only from a `platform_admins`
        // row + `/platform/login`.
        for local in [
            UserRole::Technician,
            UserRole::Manager,
            UserRole::Admin,
            UserRole::SuperAdmin,
        ] {
            assert_eq!(
                effective_role_from_bunyip(Some("admin"), local),
                UserRole::Admin,
                "bunyip admin must not mint a super_admin users row \
                 (regression from MAPPS-519)"
            );
        }
    }

    #[test]
    fn no_bunyip_role_ever_mints_super_admin() {
        // MAPPS-519 belt-and-braces regression: for the full cross of
        // known bunyip claims x known local roles, no branch of
        // `effective_role_from_bunyip` may return `SuperAdmin`. A
        // future accidental flip (a new bunyip role, a copy-paste of
        // the old mapping) is caught by this test rather than
        // silently reopening the shared-identity data surface in
        // production.
        //
        // The `None` branch is deliberately excluded here because it
        // preserves the local row verbatim for back-compat with the
        // legacy HS256 / standalone paths; a caller with an existing
        // `local = SuperAdmin` still needs to see it come back
        // unchanged there. Migration 133 already deletes those rows
        // in prod, so no live caller exercises that combination.
        for claim in ["admin", "subscriber", "owner", "member", "guest", ""] {
            for local in [
                UserRole::Technician,
                UserRole::Dispatcher,
                UserRole::Sales,
                UserRole::Finance,
                UserRole::Manager,
                UserRole::Admin,
                UserRole::SuperAdmin,
            ] {
                let effective = effective_role_from_bunyip(Some(claim), local);
                assert_ne!(
                    effective,
                    UserRole::SuperAdmin,
                    "bunyip_role={claim:?} local={local:?} must not \
                     promote to SuperAdmin (regression from MAPPS-519)"
                );
            }
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
