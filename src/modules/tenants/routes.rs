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
use super::{
    CreateTenantRequest, TenantBranding, TenantResponse, TenantService, TenantUsage,
    UpdateTenantRequest,
};
use crate::modules::auth::{RequireAuth, RequireSuperAdmin, TenantId, TenantScoped, UserRole};
use crate::modules::settings::{ModuleConfigResponse, SettingsService, UpsertModuleConfigRequest};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

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
}

/// Create the tenant management router. `settings_service` is threaded
/// in so the `/tenants/:id/modules/:module` endpoints delegate to the
/// canonical SettingsService (PMS-113 AC2).
pub fn tenant_routes(
    tenant_service: TenantService,
    settings_service: Arc<SettingsService>,
) -> Router {
    let state = TenantRouterState {
        tenant_service: Arc::new(tenant_service),
        logos: Arc::new(TenantLogoStore::new(TenantLogoConfig::from_env())),
        settings_service,
    };

    Router::new()
        .route("/", get(list_tenants))
        .route("/", post(create_tenant))
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
    _super_admin: RequireSuperAdmin,
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
    _super_admin: RequireSuperAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateTenantRequest>,
) -> AppResult<Json<TenantResponse>> {
    request.validate()?;

    let tenant = state.tenant_service.create_tenant(&request, &ctx).await?;

    Ok(Json(tenant.into()))
}

/// Get tenant by ID
async fn get_tenant(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<TenantResponse>> {
    // Super admin can view any tenant, others can only view their own
    if user.role != UserRole::SuperAdmin && user.tenant_id != tenant_id {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    // SAFETY (PMS-261): this super-admin surface deliberately addresses an
    // arbitrary path `tenant_id`, not the caller's own claim. The role guard
    // above is the gate (super-admin, or same-tenant), so `from_trusted` is
    // sound: a non-super-admin can only reach this with `tenant_id ==
    // user.tenant_id`.
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
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    let mut file: Option<(String, Vec<u8>)> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart parse: {e}")))?
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
            .map_err(|e| AppError::BadRequest(format!("multipart read: {e}")))?;
        file = Some((mime, bytes.to_vec()));
        break;
    }
    let (mime, bytes) =
        file.ok_or_else(|| AppError::BadRequest("missing 'file' part in multipart body".into()))?;

    let tenant_id = user.tenant();
    let stored_mime = state.logos.store(tenant_id.get(), &mime, &bytes).await?;

    // The bytes land first, so a failed write never leaves branding pointing at
    // a logo that is not there.
    let existing = state.tenant_service.get_tenant(tenant_id).await?;
    let branding = TenantBranding {
        logo_url: Some(logo_path(tenant_id.get())),
        logo_mime: Some(stored_mime.to_string()),
        ..existing.branding
    };
    let tenant = state
        .tenant_service
        .update_tenant(
            tenant_id,
            &UpdateTenantRequest {
                name: None,
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
        return Err(AppError::Forbidden("Access denied".to_string()));
    }
    let tenant_id = user.tenant();
    let existing = state.tenant_service.get_tenant(tenant_id).await?;
    let branding = TenantBranding {
        logo_url: None,
        logo_mime: None,
        ..existing.branding
    };
    let tenant = state
        .tenant_service
        .update_tenant(
            tenant_id,
            &UpdateTenantRequest {
                name: None,
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
        return Err(AppError::Forbidden("Access denied".to_string()));
    }
    request.validate()?;
    let tenant = state
        .tenant_service
        .update_tenant(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(tenant.into()))
}

/// Update tenant
async fn update_tenant(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpdateTenantRequest>,
) -> AppResult<Json<TenantResponse>> {
    // Super admin can update any tenant, admins can update their own
    if user.role != UserRole::SuperAdmin && !(user.tenant_id == tenant_id && user.role.is_admin()) {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    request.validate()?;

    // SAFETY (PMS-261): super-admin (any tenant) or same-tenant admin, gated by
    // the role guard above; the arbitrary path `tenant_id` is sound to bridge
    // via `from_trusted` only because of that guard.
    let tenant = state
        .tenant_service
        .update_tenant(TenantId::from_trusted(tenant_id), &request, &ctx)
        .await?;

    Ok(Json(tenant.into()))
}

/// Suspend tenant (super admin only)
async fn suspend_tenant(
    State(state): State<TenantRouterState>,
    _super_admin: RequireSuperAdmin,
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

/// Activate tenant (super admin only)
async fn activate_tenant(
    State(state): State<TenantRouterState>,
    _super_admin: RequireSuperAdmin,
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

/// Get tenant usage statistics
async fn get_tenant_usage(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<TenantUsage>> {
    // Super admin can view any tenant, admins can view their own
    if user.role != UserRole::SuperAdmin && user.tenant_id != tenant_id {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    // SAFETY (PMS-261): super-admin (any tenant) or same-tenant caller, gated by
    // the guard above; arbitrary path `tenant_id` bridged via `from_trusted`.
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
    RequireAuth(user): RequireAuth,
    Path((tenant_id, module)): Path<(Uuid, String)>,
) -> AppResult<Json<ModuleConfigResponse>> {
    if user.role != UserRole::SuperAdmin && user.tenant_id != tenant_id {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    // SAFETY (PMS-261): super-admin (any tenant) or same-tenant caller, gated by
    // the guard above; arbitrary path `tenant_id` bridged via `from_trusted`.
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
    RequireAuth(user): RequireAuth,
    Path((tenant_id, module)): Path<(Uuid, String)>,
    Json(request): Json<UpsertModuleConfigRequest>,
) -> AppResult<Json<ModuleConfigResponse>> {
    if user.role != UserRole::SuperAdmin && !(user.tenant_id == tenant_id && user.role.is_admin()) {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    // SAFETY (PMS-261): super-admin (any tenant) or same-tenant admin, gated by
    // the guard above; arbitrary path `tenant_id` bridged via `from_trusted`.
    let config = state
        .settings_service
        .upsert_module_config(TenantId::from_trusted(tenant_id), &module, &request)
        .await?;

    Ok(Json(config))
}
