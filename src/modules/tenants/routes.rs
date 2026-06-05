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
use crate::modules::auth::{RequireAuth, UserRole};
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
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TenantResponse>>> {
    // Only super admins can list all tenants
    if user.role != UserRole::SuperAdmin {
        return Err(AppError::Forbidden(
            "Super admin access required".to_string(),
        ));
    }

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
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateTenantRequest>,
) -> AppResult<Json<TenantResponse>> {
    if user.role != UserRole::SuperAdmin {
        return Err(AppError::Forbidden(
            "Super admin access required".to_string(),
        ));
    }

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

    let tenant = state.tenant_service.get_tenant(tenant_id).await?;

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

    let tenant = state
        .tenant_service
        .update_tenant(tenant_id, &request, &ctx)
        .await?;

    Ok(Json(tenant.into()))
}

/// Suspend tenant (super admin only)
async fn suspend_tenant(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<()> {
    if user.role != UserRole::SuperAdmin {
        return Err(AppError::Forbidden(
            "Super admin access required".to_string(),
        ));
    }

    state.tenant_service.suspend_tenant(tenant_id).await?;

    Ok(())
}

/// Activate tenant (super admin only)
async fn activate_tenant(
    State(state): State<TenantRouterState>,
    RequireAuth(user): RequireAuth,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<()> {
    if user.role != UserRole::SuperAdmin {
        return Err(AppError::Forbidden(
            "Super admin access required".to_string(),
        ));
    }

    state.tenant_service.activate_tenant(tenant_id).await?;

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

    let usage = state.tenant_service.get_tenant_usage(tenant_id).await?;

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

    let config = state
        .settings_service
        .get_module_config(tenant_id, &module)
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

    let config = state
        .settings_service
        .upsert_module_config(tenant_id, &module, &request)
        .await?;

    Ok(Json(config))
}
