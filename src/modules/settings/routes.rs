//! Settings HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use validator::Validate;

use super::models::*;
use super::service::SettingsService;
use crate::db::Database;
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::email::SharedMailer;
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct SettingsRouterState {
    pub service: Arc<SettingsService>,
    // PMS-638: the typed email-settings endpoint needs raw DB access (the
    // config lives on the system tenant, encrypted), the AES-256-GCM key to
    // en/decrypt the SMTP password, and the live mailer handle to hot-swap
    // after a change.
    pub db: Database,
    pub enc_key: [u8; 32],
    pub shared_mailer: Arc<SharedMailer>,
}

pub fn settings_routes(
    service: Arc<SettingsService>,
    db: Database,
    enc_key: [u8; 32],
    shared_mailer: Arc<SharedMailer>,
) -> Router {
    let state = SettingsRouterState {
        service,
        db,
        enc_key,
        shared_mailer,
    };
    Router::new()
        // PMS-115 tenant settings list (paginated across categories).
        // The PMS-113 PR added `/settings/{category}` for category
        // scoping below; the legacy `DELETE /settings/{id}` route was
        // dropped because axum's matchit treats `{id}` and `{category}`
        // as the same path shape and refused to register both. Delete
        // now lives at `DELETE /settings/{category}/{key}` per AC1.
        .route("/settings", get(list_settings).put(upsert_setting))
        // PMS-116 module configs. PMS-113 AC2: the tenants-API
        // `/api/v1/tenants/:tenant_id/modules/:module` surface
        // delegates to the same SettingsService instance, so this is
        // the single canonical write path even though both URL shapes
        // exist.
        .route("/settings/modules", get(list_module_configs))
        .route(
            "/settings/modules/{module}",
            get(get_module_config).put(upsert_module_config),
        )
        // PMS-638: typed email settings (system-tenant config, encrypted SMTP
        // password, live mailer swap on write). A literal route registered
        // before `/settings/{category}` so it wins over the generic matcher.
        .route("/settings/email", get(get_email).put(put_email))
        // PMS-788: send-a-test-email action (literal, before the generic
        // /settings/{category}/{key} matcher). Lets an operator exercise email
        // without a password reset.
        .route("/settings/email/test-send", post(post_email_test_send))
        // PMS-789: the deployment-wide product name. Literal, so it is matched
        // before the generic `/settings/{category}` below - which writes the
        // CALLER's tenant and is therefore not a way to set a system value.
        .route("/settings/app-name", get(get_app_name).put(put_app_name))
        // PMS-113 AC1: category- and per-key tenant_settings endpoints.
        // Placed AFTER /settings/modules so the literal "modules"
        // segment matches the module routes first and only a non-
        // "modules" category reaches `get_settings_by_category`.
        .route("/settings/{category}", get(get_settings_by_category))
        .route(
            "/settings/{category}/{key}",
            get(get_setting)
                .put(put_setting)
                .delete(delete_setting_by_key),
        )
        .with_state(state)
}

/// PMS-638: read the deployment-wide email settings (admin only). The SMTP
/// password is never returned, only whether one is set.
async fn get_email(
    State(s): State<SettingsRouterState>,
    _admin: RequireAdmin,
) -> AppResult<Json<super::email::EmailSettingsView>> {
    Ok(Json(super::email::get_email_settings(&s.db).await?))
}

/// PMS-638: write the deployment-wide email settings (admin only), then rebuild
/// and hot-swap the live mailer so the change takes effect without a restart.
async fn put_email(
    State(s): State<SettingsRouterState>,
    _admin: RequireAdmin,
    Json(input): Json<super::email::EmailSettingsInput>,
) -> AppResult<Json<super::email::EmailSettingsView>> {
    let view = super::email::put_email_settings(&s.db, &s.enc_key, input).await?;
    super::email::rebuild_and_swap(&s.db, &s.enc_key, &s.shared_mailer).await?;
    Ok(Json(view))
}

/// PMS-788: send a one-off test email to `req.to` through the live mailer, so an
/// operator can confirm outbound email without triggering a password reset.
/// A malformed address or an SMTP failure surfaces as the mailer's error
/// rather than being swallowed.
async fn post_email_test_send(
    State(s): State<SettingsRouterState>,
    _admin: RequireAdmin,
    Json(req): Json<super::email::TestEmailRequest>,
) -> AppResult<axum::http::StatusCode> {
    use crate::utils::email::Mailer;
    let app = crate::utils::app_name::app_name();
    s.shared_mailer
        .send_text(
            &req.to,
            &format!("{app} test email"),
            &format!(
                "This is a test email from {app}. If you received it, outbound email is working."
            ),
        )
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// PMS-789: read the deployment-wide product name (admin only).
async fn get_app_name(
    State(s): State<SettingsRouterState>,
    _admin: RequireAdmin,
) -> AppResult<Json<super::app_name::AppNameView>> {
    Ok(Json(super::app_name::get_app_name_settings(&s.db).await?))
}

/// PMS-789: write the deployment-wide product name (admin only). The write
/// refreshes the process cache, so the next mail sent and the next 404 page
/// rendered carry the new name with no restart.
async fn put_app_name(
    State(s): State<SettingsRouterState>,
    _admin: RequireAdmin,
    Json(input): Json<super::app_name::AppNameInput>,
) -> AppResult<Json<super::app_name::AppNameView>> {
    Ok(Json(
        super::app_name::put_app_name_settings(&s.db, input).await?,
    ))
}

async fn list_settings(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TenantSettingResponse>>> {
    let (items, total) = s
        .service
        .list_tenant_settings(u.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn upsert_setting(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Json(req): Json<UpsertTenantSettingRequest>,
) -> AppResult<Json<TenantSettingResponse>> {
    req.validate()?;
    // PMS-776: the body-carried write of the same rows the per-key route below
    // validates. Without this a branding value reached `tenant_settings`
    // unchecked through the older URL shape.
    validate_setting_value(&req.category, &req.key, &req.value)?;
    Ok(Json(
        s.service.upsert_tenant_setting(u.tenant(), &req).await?,
    ))
}

async fn list_module_configs(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ModuleConfigResponse>>> {
    let (items, total) = s
        .service
        .list_module_configs(u.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_module_config(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(module): Path<String>,
) -> AppResult<Json<ModuleConfigResponse>> {
    Ok(Json(
        s.service.get_module_config(u.tenant(), &module).await?,
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
            .upsert_module_config(u.tenant(), &module, &req)
            .await?,
    ))
}

// PMS-113 AC1: category + per-key tenant_settings ---------------------------

async fn get_settings_by_category(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(category): Path<String>,
) -> AppResult<Json<Vec<TenantSettingResponse>>> {
    Ok(Json(
        s.service
            .list_settings_by_category(u.tenant(), &category)
            .await?,
    ))
}

async fn get_setting(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    Path((category, key)): Path<(String, String)>,
) -> AppResult<Json<TenantSettingResponse>> {
    Ok(Json(
        s.service.get_setting(u.tenant(), &category, &key).await?,
    ))
}

async fn put_setting(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path((category, key)): Path<(String, String)>,
    Json(req): Json<PutSettingValueRequest>,
) -> AppResult<Json<TenantSettingResponse>> {
    validate_setting_value(&category, &key, &req.value)?;
    Ok(Json(
        s.service
            .put_setting(u.tenant(), &category, &key, req.value)
            .await?,
    ))
}

async fn delete_setting_by_key(
    State(s): State<SettingsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path((category, key)): Path<(String, String)>,
) -> AppResult<()> {
    s.service
        .delete_setting_by_key(u.tenant(), &category, &key)
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::utils::email::{LogMailer, Mailer, SharedMailer};

    use super::super::email::TestEmailRequest;

    #[test]
    fn test_email_request_deserializes_the_address() {
        let req: TestEmailRequest =
            serde_json::from_str(r#"{"to":"ops@example.com"}"#).expect("valid body");
        assert_eq!(req.to, "ops@example.com");
    }

    // PMS-788: the send-test handler routes the address through the live mailer
    // (`SharedMailer::send_text`), the same primitive the notifications worker
    // uses. LogMailer records rather than sends, so this exercises the path
    // without SMTP.
    #[tokio::test]
    async fn send_test_routes_through_the_mailer() {
        let shared = SharedMailer::new(Arc::new(LogMailer));
        shared
            .send_text("ops@example.com", "Mokosh test email", "body")
            .await
            .expect("LogMailer send succeeds");
    }
}
