//! Tenant API routes (Super Admin only)

use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::logo::{logo_path, TenantLogoConfig, TenantLogoStore};
use super::organization::organization_update;
use super::{
    CreateTenantRequest, OrganizationProfileRequest, TenantAdminInfo, TenantResponse,
    TenantService, TenantUsage, UpdateTenantAdminRequest, UpdateTenantRequest,
};
use crate::modules::auth::{
    AuthService, CurrentUser, RequireAuth, RequireAuthState, TenantId, TenantScoped,
};
use crate::modules::platform::RequirePlatformAdmin;

/// MAPPS-518: extractor that lets a tenant `users` caller AND a
/// `/platform/login` bearer through the same handler. The former
/// `role='super_admin'` cross-tenant bypass is retired, but the
/// cross-tenant admin surface it enabled (viewing / editing an
/// arbitrary tenant from the console) is preserved via the
/// platform-plane bearer. Handlers that used to check
/// `user.role == UserRole::SuperAdmin || user.tenant_id == tenant_id`
/// now consume `TenantOrPlatformCaller` and call one of its
/// `require_*` helpers instead.
// Merge cleanup: box the large variant in a follow-up (out of scope for the route-overlap fix)
#[allow(clippy::large_enum_variant)]
pub enum TenantOrPlatformCaller {
    Platform,
    Tenant(CurrentUser),
}

impl<S> axum::extract::FromRequestParts<S> for TenantOrPlatformCaller
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        if RequirePlatformAdmin::from_request_parts(parts, state)
            .await
            .is_ok()
        {
            return Ok(TenantOrPlatformCaller::Platform);
        }
        let RequireAuth(user) = RequireAuth::from_request_parts(parts, state).await?;
        Ok(TenantOrPlatformCaller::Tenant(user))
    }
}

impl TenantOrPlatformCaller {
    /// Read-side gate: platform admin can read any tenant; a tenant
    /// caller can read only their own.
    fn require_read_access(&self, tenant_id: Uuid) -> AppResult<()> {
        match self {
            TenantOrPlatformCaller::Platform => Ok(()),
            TenantOrPlatformCaller::Tenant(u) if u.tenant_id == tenant_id => Ok(()),
            _ => Err(AppError::Forbidden("You do not have permission to perform this action.".to_string())),
        }
    }

    /// Write-side gate: platform admin can write any tenant; a tenant
    /// caller must be the admin of their own tenant.
    fn require_admin_write_access(&self, tenant_id: Uuid) -> AppResult<()> {
        match self {
            TenantOrPlatformCaller::Platform => Ok(()),
            TenantOrPlatformCaller::Tenant(u) if u.tenant_id == tenant_id && u.role.is_admin() => {
                Ok(())
            }
            _ => Err(AppError::Forbidden("You do not have permission to perform this action.".to_string())),
        }
    }
}
use crate::modules::settings::{ModuleConfigResponse, SettingsService, UpsertModuleConfigRequest};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};
use mokosh_types::auth::{AdditionalTenantRequest, LoginResponse, SelfServeTenantRequest};

#[derive(Clone)]
pub struct TenantRouterState {
    pub tenant_service: Arc<TenantService>,
    /// MAPPS-429: on-disk store for the tenant logo.
    pub logos: Arc<TenantLogoStore>,
    // PMS-113 AC2: the module-config handlers on the tenants surface
    // delegate to SettingsService so there's a single canonical writer
    // for `module_config`. SettingsService is wrapped in an Arc by its
    // own router state; we Arc it here too so the clone is cheap and
    // the two routers share the same instance.
    pub settings_service: Arc<SettingsService>,
    /// MAPPS-493 (MAPPS-474 phase 4): needed by the `/tenants/self-serve`
    /// handler so it can decode an identity_token (from the phase-3
    /// `needs_setup` login branch) and mint a full session for the
    /// admin of the freshly created tenant. Shared with the auth
    /// router via the same `Arc<AuthService>` created in `api/router.rs`.
    pub auth_service: Arc<AuthService>,
}

/// Create the tenant management router. `settings_service` is threaded
/// in so the `/tenants/:id/modules/:module` endpoints delegate to the
/// canonical SettingsService (PMS-113 AC2).
pub fn tenant_routes(
    tenant_service: TenantService,
    settings_service: Arc<SettingsService>,
    auth_service: Arc<AuthService>,
) -> Router {
    // PMS-957: the authenticated tree is where a logo is uploaded and removed,
    // so it is the one that records what is stored.
    let logos =
        TenantLogoStore::new(TenantLogoConfig::from_env()).with_ledger(tenant_service.db.clone());
    let state = TenantRouterState {
        tenant_service: Arc::new(tenant_service),
        logos: Arc::new(logos),
        settings_service,
        auth_service,
    };

    Router::new()
        .route("/", get(list_tenants))
        .route("/", post(create_tenant))
        // MAPPS-493 (MAPPS-474 phase 4): PUBLIC (no RequireAuth); the
        // handler decodes an identity_token from the phase-3
        // `needs_setup` login branch and returns a full `LoginResponse`
        // scoped to the freshly created tenant.
        .route("/self-serve", post(self_serve_tenant))
        // MAPPS-494 (MAPPS-474 phase 5): authenticated identity creates
        // an ADDITIONAL organization. Bearer required; the caller
        // becomes admin in the new tenant. Distinct from `self-serve`
        // (which is for the zero-membership `needs_setup` login branch
        // and returns a full session) because an authenticated caller
        // already has a session and can pick when to switch to the new
        // tenant via `/auth/switch-tenant/:id`.
        .route("/additional", post(create_additional_tenant))
        // PMS-751: the caller's OWN tenant, addressed without an id.
        //
        // Declared before the `{tenant_id}` routes for readability only; axum
        // matches a static segment ahead of a dynamic one regardless of
        // declaration order, so `current` can never be parsed as a uuid.
        //
        // These exist because the SPA does not reliably know its own tenant id.
        // It reads one from the `mokosh_tenant_id` id_token claim, which bunyip
        // only mints for a client configured with `tenant_claim_name`, and
        // falls back to the nil uuid otherwise. The organization settings page
        // then asked for tenant 00000000-0000-0000-0000-000000000000 and got a
        // 404. The server knows the caller's tenant on every request; making
        // the browser supply it was the defect.
        .route("/current", get(get_current_tenant))
        .route("/current", put(update_current_tenant))
        // PMS-896: the organisation record, submitted whole. Separate from the
        // PATCH above because this is the one surface that states which fields
        // an account must supply; see `super::organization`. Read back off
        // `GET /current`, which already returns the name and the branding.
        .route("/current/organization", put(update_current_organization))
        // MAPPS-429: the organisation's logo. Written here, read from the
        // PUBLIC router below, because the two places it has to appear (a
        // client's browser on the request-form page, a client's mail client)
        // have no session.
        .route("/current/logo", put(upload_current_logo))
        .route("/current/logo", delete(delete_current_logo))
        .route("/{tenant_id}", get(get_tenant))
        .route("/{tenant_id}", put(update_tenant))
        .route("/{tenant_id}/suspend", post(suspend_tenant))
        .route("/{tenant_id}/activate", post(activate_tenant))
        // mokosh-contact-login: the /cancel + /admin routes + the
        // resend-welcome route (MAPPS-558 / MAPPS-450 / MAPPS-448)
        // retired with the Clients-tab UI in prompt 001. Handlers
        // stay in the file as dead code and will be swept in a
        // follow-up cleanup pass.
        .route("/{tenant_id}/usage", get(get_tenant_usage))
        // Audit F5: expose existing service-level module-config helpers
        // over HTTP so the client's settings/integrations page can read
        // and toggle per-module config.
        .route("/{tenant_id}/modules/{module}", get(get_module_config))
        .route("/{tenant_id}/modules/{module}", put(update_module_config))
        .with_state(state)
}

/// List all tenants (super admin only)
async fn list_tenants(
    State(state): State<TenantRouterState>,
    _platform: RequirePlatformAdmin,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TenantResponse>>> {
    let (tenants, total) = state.tenant_service.list_tenants(&pagination).await?;

    let response = PaginatedResponse::from_params(
        tenants.into_iter().map(TenantResponse::from).collect(),
        &pagination,
        total,
    );

    Ok(Json(response))
}

/// Create a new tenant (super admin only)
async fn create_tenant(
    State(state): State<TenantRouterState>,
    _platform: RequirePlatformAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateTenantRequest>,
) -> AppResult<Json<TenantResponse>> {
    request.validate()?;

    let tenant = state.tenant_service.create_tenant(&request, &ctx).await?;

    Ok(Json(tenant.into()))
}

/// MAPPS-493 (MAPPS-474 phase 4): trade an identity_token (from the
/// phase-3 `needs_setup` login branch) for a new organization + a full
/// session scoped to it. PUBLIC route (no bearer required); the
/// identity_token in the body IS the authentication.
///
/// Refuses when the caller already holds at least one active membership
/// (they should use the in-app "Create org" button instead — that lands
/// in phase 5 as part of the switcher work).
async fn self_serve_tenant(
    State(state): State<TenantRouterState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<SelfServeTenantRequest>,
) -> AppResult<Json<LoginResponse>> {
    request.validate()?;

    // 1. Authenticate via identity_token. Wrong typ / expired -> 401.
    let (identity_id, email) = state
        .auth_service
        .decode_identity_token(&request.identity_token)?;

    // 2. Load the identity row for the name fields + password hash.
    //    The trigger from phase 1 uses the identity's password_hash to
    //    keep the new users row in sync with what the identity plane
    //    already believes.
    let pool = state.auth_service.db().migrator_pool();
    let identity = crate::db::identity::IdentityRepo::find_by_id(pool, identity_id)
        .await
        .map_err(|_| AppError::Unauthorized)?
        .ok_or(AppError::Unauthorized)?;
    if identity.status != "active" {
        return Err(AppError::Unauthorized);
    }

    // 3. Refuse when the identity already holds active memberships. Guards
    //    against replaying a needs_setup identity_token after the identity
    //    has been placed. Phase 5 will add an in-app "Create org" button
    //    for authenticated identities that goes through a different route.
    let existing = crate::db::identity::MembershipRepo::list_active_for_identity(pool, identity_id)
        .await
        .map_err(|_| AppError::Unauthorized)?;
    if !existing.is_empty() {
        return Err(AppError::conflict(
            "You already belong to an organization. Sign in and use the in-app Create button instead.",
        ));
    }

    // 4. Create the tenant + admin users row. Phase-1 trigger drops the
    //    matching `tenant_memberships` row so the identity is admin in
    //    the new tenant immediately.
    let (_tenant, _admin_id) = state
        .tenant_service
        .create_tenant_for_identity(
            &identity.email,
            &identity.first_name,
            &identity.last_name,
            identity.password_hash.as_deref(),
            &request.tenant_name,
            request.tenant_slug.as_deref(),
            &ctx,
        )
        .await?;

    // 5. Mint a full session for the fresh admin. Client-side
    //    `install_session` handles the wire response identically to
    //    the auto-scope login branch, so the SPA lands directly on
    //    the dashboard scoped to the new tenant.
    let ip_address = Some(
        crate::utils::client_ip::extract_client_ip(
            addr.ip(),
            &headers,
            crate::utils::client_ip::trusted_proxies(),
        )
        .to_string(),
    );
    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let response = state
        .auth_service
        .mint_session_for_membership(_tenant.id, &email, ip_address, user_agent)
        .await?;
    Ok(Json(response))
}

/// MAPPS-494 (MAPPS-474 phase 5): authenticated identity creates an
/// additional organization. The caller becomes admin in the fresh
/// tenant. Returns the Tenant DTO; the caller separately POSTs to
/// `/auth/switch-tenant/:id` to move their session into it.
///
/// Unlike `self_serve_tenant`, this handler REQUIRES a bearer session
/// (`RequireAuthState`) and does NOT return a fresh session. The client
/// keeps its existing session and just refetches memberships +
/// optionally switches when ready.
async fn create_additional_tenant(
    State(state): State<TenantRouterState>,
    RequireAuthState(auth_state): RequireAuthState,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<AdditionalTenantRequest>,
) -> AppResult<Json<TenantResponse>> {
    request.validate()?;

    let identity_id = auth_state.identity_id.ok_or(AppError::Unauthorized)?;

    // Load the identity row for first/last name + password_hash. Same
    // shape as `self_serve_tenant`: users row in the new tenant must
    // mirror the identity plane so login stays coherent.
    let pool = state.auth_service.db().migrator_pool();
    let identity = crate::db::identity::IdentityRepo::find_by_id(pool, identity_id)
        .await
        .map_err(|_| AppError::Unauthorized)?
        .ok_or(AppError::Unauthorized)?;
    if identity.status != "active" {
        return Err(AppError::Unauthorized);
    }

    let (tenant, _admin_id) = state
        .tenant_service
        .create_tenant_for_identity(
            &identity.email,
            &identity.first_name,
            &identity.last_name,
            identity.password_hash.as_deref(),
            &request.tenant_name,
            request.tenant_slug.as_deref(),
            &ctx,
        )
        .await?;

    Ok(Json(tenant.into()))
}

/// Get tenant by ID. MAPPS-518: platform admin OR same-tenant caller.
async fn get_tenant(
    State(state): State<TenantRouterState>,
    caller: TenantOrPlatformCaller,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<TenantResponse>> {
    caller.require_read_access(tenant_id)?;

    // SAFETY (PMS-261 + MAPPS-518): allowed via same-tenant guard OR
    // platform admin; the arbitrary path `tenant_id` is sound to
    // bridge because the check above pins it.
    let tenant = state
        .tenant_service
        .get_tenant(TenantId::from_trusted(tenant_id))
        .await?;

    Ok(Json(tenant.into()))
}

/// MAPPS-429: the unauthenticated read side of the tenant logo.
///
/// Mounted by the caller under `/api/v1/public`. Separate router because the
/// authenticated tree sits behind `AuthMiddleware`, and a mail client fetching
/// an image will never carry a session.
pub fn public_tenant_routes(tenant_service: TenantService) -> Router {
    let state = PublicTenantState {
        tenant_service: Arc::new(tenant_service),
        // No ledger: this router only READS a logo, and recording is a
        // property of storing one.
        logos: Arc::new(TenantLogoStore::new(TenantLogoConfig::from_env())),
    };
    Router::new()
        .route("/tenants/{tenant_id}/logo", get(get_public_logo))
        .with_state(state)
}

#[derive(Clone)]
struct PublicTenantState {
    tenant_service: Arc<TenantService>,
    logos: Arc<TenantLogoStore>,
}

/// Serve a tenant's logo to anyone holding the tenant id.
///
/// A company logo is the least private asset an MSP owns, and this is the only
/// way it can reach an email. A tenant with no logo is a 404, identical to a
/// tenant id that does not exist, so this does not answer "does this tenant
/// exist" any more precisely than it has to.
async fn get_public_logo(
    State(s): State<PublicTenantState>,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Response> {
    // SAFETY (PMS-285): pre-auth, cross-tenant read of the RLS-exempt `tenants`
    // root, resolved by primary key. There is no session to derive a tenant
    // from: resolving the tenant IS the request. Nothing tenant-scoped is read.
    let tenant = s
        .tenant_service
        .get_tenant(TenantId::from_trusted(tenant_id))
        .await
        .map_err(|_| AppError::NotFound("Logo".to_string()))?;
    let mime = tenant
        .branding
        .logo_mime
        .clone()
        .ok_or_else(|| AppError::NotFound("Logo".to_string()))?;
    let bytes = s.logos.read(tenant_id, &mime).await?;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime),
            // Immutable is wrong here (the file is replaced in place), so this
            // is a short cache: long enough that a mail client rendering the
            // same message twice does not refetch, short enough that a logo
            // change is visible the same day.
            (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
        ],
        bytes,
    )
        .into_response())
}

/// MAPPS-429: replace the caller's organisation logo.
///
/// Admin-gated like the rename: the logo is what every client sees on the forms
/// and email this tenant sends, so it is tenant-wide configuration.
async fn upload_current_logo(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    mut multipart: Multipart,
) -> AppResult<Json<TenantResponse>> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to do that".to_string(),
        ));
    }

    let mut file: Option<(String, Vec<u8>)> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Multipart parse: {e}")))?
    {
        if field.name().unwrap_or_default() != "file" {
            continue;
        }
        let mime = field
            .content_type()
            .map(str::to_string)
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let bytes = field
            .bytes()
            .await
            .map_err(|e| AppError::BadRequest(format!("Multipart read: {e}")))?;
        file = Some((mime, bytes.to_vec()));
        break;
    }
    let (mime, bytes) =
        file.ok_or_else(|| AppError::BadRequest("Missing 'file' part in multipart body".into()))?;

    let tenant_id = user.tenant();
    let stored_mime = state.logos.store(tenant_id.get(), &mime, &bytes).await?;

    // The bytes land first, so a failed write never leaves branding pointing at
    // a logo that is not there.
    //
    // PMS-758: only the two keys this owns. `branding` is merged, so reading
    // the document to write it back would be both unnecessary and a way to
    // clobber a concurrent edit from the settings page.
    let branding = serde_json::json!({
        "logo_url": logo_path(tenant_id.get()),
        "logo_mime": stored_mime,
    });
    let tenant = state
        .tenant_service
        .update_tenant(
            tenant_id,
            &UpdateTenantRequest {
                name: None,
                slug: None,
                billing_email: None,
                billing_contact_name: None,
                settings: None,
                branding: Some(branding),
            },
            &ctx,
        )
        .await?;
    Ok(Json(tenant.into()))
}

/// Remove the logo. Clears the branding pointer first: a file left on disk that
/// nothing points at is invisible, while a pointer to a deleted file is a
/// broken image in every email the tenant sends.
async fn delete_current_logo(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
) -> AppResult<Json<TenantResponse>> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to do that".to_string(),
        ));
    }
    let tenant_id = user.tenant();
    // PMS-758: explicit nulls, which is how a merged document clears a key.
    let branding = serde_json::json!({ "logo_url": null, "logo_mime": null });
    let tenant = state
        .tenant_service
        .update_tenant(
            tenant_id,
            &UpdateTenantRequest {
                name: None,
                slug: None,
                billing_email: None,
                billing_contact_name: None,
                settings: None,
                branding: Some(branding),
            },
            &ctx,
        )
        .await?;
    state.logos.remove(tenant_id.get()).await;
    Ok(Json(tenant.into()))
}

/// PMS-751: read the caller's own tenant.
///
/// No path id and no role gate beyond being signed in: the tenant this returns
/// is the one the caller is already authenticated against, so there is nothing
/// here they could not learn from any other tenant-scoped response. The
/// cross-tenant read stays on `GET /{tenant_id}`, which keeps its super-admin
/// guard.
async fn get_current_tenant(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<TenantResponse>> {
    let tenant = state.tenant_service.get_tenant(user.tenant()).await?;
    Ok(Json(tenant.into()))
}

/// PMS-751: rename the caller's own tenant.
///
/// Admin-gated, matching `PUT /{tenant_id}`: the name is customer-facing (it is
/// the "from" in every request-form and invitation email), so it is tenant-wide
/// configuration rather than personal preference. A super_admin is an admin for
/// this purpose, so the check is `is_admin()` alone; the cross-tenant case is
/// what `PUT /{tenant_id}` is for.
async fn update_current_tenant(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpdateTenantRequest>,
) -> AppResult<Json<TenantResponse>> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to do that".to_string(),
        ));
    }
    request.validate()?;
    let tenant = state
        .tenant_service
        .update_tenant(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(tenant.into()))
}

/// PMS-896: save the caller's organisation record.
///
/// Name, contact phone and contact email are required; the contact name and the
/// website are optional and are cleared when the submission omits them. Same
/// admin gate as the rename it performs: the organisation name, contact and
/// website are what every client sees on the forms and email this tenant sends.
/// A non-admin's onboarding does not reach here (MAPPS-524).
async fn update_current_organization(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<OrganizationProfileRequest>,
) -> AppResult<Json<TenantResponse>> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to do that".to_string(),
        ));
    }
    let update = organization_update(&request)?;
    let tenant = state
        .tenant_service
        .update_tenant(user.tenant(), &update, &ctx)
        .await?;
    Ok(Json(tenant.into()))
}

/// Update tenant
async fn update_tenant(
    State(state): State<TenantRouterState>,
    caller: TenantOrPlatformCaller,
    ctx: crate::modules::audit::AuditCtx,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpdateTenantRequest>,
) -> AppResult<Json<TenantResponse>> {
    // MAPPS-518: platform admin OR same-tenant admin.
    caller.require_admin_write_access(tenant_id)?;

    request.validate()?;

    // SAFETY (PMS-261 + MAPPS-518): admin-scoped by the guard above.
    let tenant = state
        .tenant_service
        .update_tenant(TenantId::from_trusted(tenant_id), &request, &ctx)
        .await?;

    Ok(Json(tenant.into()))
}

/// Suspend tenant (super admin only)
async fn suspend_tenant(
    State(state): State<TenantRouterState>,
    _platform: RequirePlatformAdmin,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<()> {
    // SAFETY (PMS-261): super-admin-only path (the RequireSuperAdmin extractor
    // is the guard); the arbitrary path `tenant_id` is an administrative
    // target, not the caller's claim, so `from_trusted` is the sanctioned
    // bridge.
    state
        .tenant_service
        .suspend_tenant(TenantId::from_trusted(tenant_id))
        .await?;

    Ok(())
}

/// MAPPS-558: cancel a client (super admin only). Reversible via
/// `activate_tenant`; both are the same guard shape.
// Contact-plane retirement fallout; retained pending MAPPS-656/657 restoration decision
#[allow(dead_code)]
async fn cancel_tenant(
    State(state): State<TenantRouterState>,
    _platform: RequirePlatformAdmin,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<()> {
    // SAFETY (PMS-261): super-admin-only path (the RequirePlatformAdmin
    // extractor is the guard); the arbitrary path `tenant_id` is an
    // administrative target, bridged via `from_trusted`.
    state
        .tenant_service
        .cancel_tenant(TenantId::from_trusted(tenant_id))
        .await?;

    Ok(())
}

/// MAPPS-450: read the tenant admin's `users` row (super admin only).
// Contact-plane retirement fallout; retained pending MAPPS-656/657 restoration decision
#[allow(dead_code)]
async fn get_tenant_admin(
    State(state): State<TenantRouterState>,
    _platform: RequirePlatformAdmin,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<TenantAdminInfo>> {
    // SAFETY (PMS-261): super-admin-only path; the arbitrary `tenant_id`
    // is an administrative target, bridged via `from_trusted`.
    let admin = state
        .tenant_service
        .get_tenant_admin(TenantId::from_trusted(tenant_id))
        .await?;
    Ok(Json(admin))
}

/// MAPPS-450: super-admin edits the tenant admin's email + name pair.
// Contact-plane retirement fallout; retained pending MAPPS-656/657 restoration decision
#[allow(dead_code)]
async fn update_tenant_admin(
    State(state): State<TenantRouterState>,
    _platform: RequirePlatformAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpdateTenantAdminRequest>,
) -> AppResult<Json<TenantAdminInfo>> {
    request.validate()?;
    // SAFETY (PMS-261): super-admin-only path via RequireSuperAdmin; the
    // arbitrary `tenant_id` is an administrative target, bridged via
    // `from_trusted`.
    let admin = state
        .tenant_service
        .update_tenant_admin(TenantId::from_trusted(tenant_id), &request, &ctx)
        .await?;
    Ok(Json(admin))
}

/// MAPPS-448: re-issue the tenant admin's welcome email (super admin only).
// Contact-plane retirement fallout; retained pending MAPPS-656/657 restoration decision
#[allow(dead_code)]
async fn resend_admin_welcome(
    State(state): State<TenantRouterState>,
    _platform: RequirePlatformAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<()> {
    // SAFETY (PMS-261): super-admin-only path via RequireSuperAdmin; the
    // arbitrary `tenant_id` is an administrative target, not the caller's
    // claim, so `from_trusted` is the sanctioned bridge.
    state
        .tenant_service
        .resend_admin_welcome(TenantId::from_trusted(tenant_id), &ctx)
        .await?;

    Ok(())
}

/// Activate tenant (super admin only)
async fn activate_tenant(
    State(state): State<TenantRouterState>,
    _platform: RequirePlatformAdmin,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<()> {
    // SAFETY (PMS-261): super-admin-only path (the RequireSuperAdmin extractor
    // is the guard); arbitrary path `tenant_id` is an administrative target,
    // bridged via `from_trusted`.
    state
        .tenant_service
        .activate_tenant(TenantId::from_trusted(tenant_id))
        .await?;

    Ok(())
}

/// Get tenant usage statistics. MAPPS-518: platform admin OR
/// same-tenant caller.
async fn get_tenant_usage(
    State(state): State<TenantRouterState>,
    caller: TenantOrPlatformCaller,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<TenantUsage>> {
    caller.require_read_access(tenant_id)?;

    // SAFETY (PMS-261 + MAPPS-518): allowed via same-tenant guard OR
    // platform admin; `from_trusted` sound.
    let usage = state
        .tenant_service
        .get_tenant_usage(TenantId::from_trusted(tenant_id))
        .await?;

    Ok(Json(usage))
}

/// Get a tenant's per-module config (audit F5).
///
/// PMS-113 AC2: delegates to the canonical `SettingsService`; the
/// authz check (super-admin OR same-tenant admin) stays here because
/// this surface deliberately exposes cross-tenant operations for
/// super-admins, while `/api/v1/settings/modules/:module` is scoped
/// implicitly to the caller's own tenant.
async fn get_module_config(
    State(state): State<TenantRouterState>,
    caller: TenantOrPlatformCaller,
    Path((tenant_id, module)): Path<(Uuid, String)>,
) -> AppResult<Json<ModuleConfigResponse>> {
    // MAPPS-518: platform admin OR same-tenant caller.
    caller.require_read_access(tenant_id)?;

    // SAFETY (PMS-261 + MAPPS-518): allowed via same-tenant guard OR
    // platform admin; `from_trusted` sound.
    let config = state
        .settings_service
        .get_module_config(TenantId::from_trusted(tenant_id), &module)
        .await?;

    Ok(Json(config))
}

/// Update a tenant's per-module config (audit F5). PMS-113 AC2:
/// delegates to the canonical `SettingsService`.
async fn update_module_config(
    State(state): State<TenantRouterState>,
    caller: TenantOrPlatformCaller,
    Path((tenant_id, module)): Path<(Uuid, String)>,
    Json(request): Json<UpsertModuleConfigRequest>,
) -> AppResult<Json<ModuleConfigResponse>> {
    // MAPPS-518: platform admin OR same-tenant admin.
    caller.require_admin_write_access(tenant_id)?;

    // SAFETY (PMS-261 + MAPPS-518): admin-scoped by the guard above.
    let config = state
        .settings_service
        .upsert_module_config(TenantId::from_trusted(tenant_id), &module, &request)
        .await?;

    Ok(Json(config))
}
