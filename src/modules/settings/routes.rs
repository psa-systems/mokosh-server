//! Settings HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{get, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::SettingsService;
use crate::modules::auth::{RequireAdmin, RequireAuth};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct SettingsRouterState {
    pub service: Arc<SettingsService>,
}

pub fn settings_routes(service: SettingsService) -> Router {
    let state = SettingsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // PMS-115 tenant settings
        .route("/settings", get(list_settings).put(upsert_setting))
        .route("/settings/{id}", axum::routing::delete(delete_setting))
        // PMS-116 module configs (parallel path; tenant module endpoint
        // continues to live at /api/v1/tenants/:tenant_id/modules/:module)
        .route("/settings/modules", get(list_module_configs))
        .route(
            "/settings/modules/{module}",
            get(get_module_config).put(upsert_module_config),
        )
        .with_state(state)
}

async fn list_settings(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<TenantSettingResponse>>> {
    Ok(Json(s.service.list_tenant_settings(u.tenant_id).await?))
}

async fn upsert_setting(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Json(req): Json<UpsertTenantSettingRequest>,
) -> AppResult<Json<TenantSettingResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.upsert_tenant_setting(u.tenant_id, &req).await?,
    ))
}

async fn delete_setting(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_tenant_setting(u.tenant_id, id).await
}

async fn list_module_configs(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<ModuleConfigResponse>>> {
    Ok(Json(s.service.list_module_configs(u.tenant_id).await?))
}

async fn get_module_config(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(module): Path<String>,
) -> AppResult<Json<ModuleConfigResponse>> {
    Ok(Json(
        s.service.get_module_config(u.tenant_id, &module).await?,
    ))
}

async fn upsert_module_config(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(module): Path<String>,
    Json(req): Json<UpsertModuleConfigRequest>,
) -> AppResult<Json<ModuleConfigResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .upsert_module_config(u.tenant_id, &module, &req)
            .await?,
    ))
}
