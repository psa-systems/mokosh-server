//! Tenant API routes (Super Admin only)

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{CreateTenantRequest, TenantResponse, TenantService, TenantUsage, UpdateTenantRequest};
use crate::modules::auth::{RequireAuth, RequireSuperAdmin, TenantId, UserRole};
use crate::modules::settings::{ModuleConfigResponse, SettingsService, UpsertModuleConfigRequest};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct TenantRouterState {
    pub tenant_service: Arc<TenantService>,
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
        settings_service,
    };

    Router::new()
        .route("/", get(list_tenants))
        .route("/", post(create_tenant))
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
