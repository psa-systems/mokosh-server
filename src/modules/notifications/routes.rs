//! Notifications HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::NotificationsService;
use crate::modules::auth::{RequireAdmin, RequireAuth};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct NotificationsRouterState {
    pub service: Arc<NotificationsService>,
}

pub fn notifications_routes(service: NotificationsService) -> Router {
    let state = NotificationsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // PMS-87 channels
        .route(
            "/notification-channels",
            get(list_channels).post(create_channel),
        )
        .route(
            "/notification-channels/{id}",
            axum::routing::delete(delete_channel),
        )
        // PMS-88 templates
        .route(
            "/notification-templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/notification-templates/{id}",
            axum::routing::delete(delete_template),
        )
        // PMS-89 user prefs
        .route(
            "/me/notification-preferences",
            get(list_user_prefs).put(upsert_user_pref),
        )
        // PMS-90 inbox
        .route("/notifications", get(list_inbox))
        .route("/notifications/{id}/read", post(mark_read))
        // PMS-91 rules
        .route("/notification-rules", get(list_rules).post(create_rule))
        .route(
            "/notification-rules/{id}",
            axum::routing::delete(delete_rule),
        )
        // PMS-92 dispatcher (manual trigger; the real worker calls
        // NotificationsService::dispatch directly)
        .route("/notifications/dispatch", post(dispatch_event))
        .with_state(state)
}

async fn list_channels(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
) -> AppResult<Json<Vec<NotificationChannelResponse>>> {
    Ok(Json(s.service.list_channels(u.tenant_id).await?))
}

async fn create_channel(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Json(req): Json<UpsertNotificationChannelRequest>,
) -> AppResult<Json<NotificationChannelResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_channel(u.tenant_id, &req).await?))
}

async fn delete_channel(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_channel(u.tenant_id, id).await
}

async fn list_templates(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<NotificationTemplateResponse>>> {
    Ok(Json(s.service.list_templates(u.tenant_id).await?))
}

async fn create_template(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Json(req): Json<UpsertNotificationTemplateRequest>,
) -> AppResult<Json<NotificationTemplateResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_template(u.tenant_id, &req).await?))
}

async fn delete_template(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_template(u.tenant_id, id).await
}

async fn list_user_prefs(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<UserNotificationPreferenceResponse>>> {
    Ok(Json(
        s.service.list_user_preferences(u.tenant_id, u.id).await?,
    ))
}

async fn upsert_user_pref(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Json(req): Json<UpsertUserNotificationPreferenceRequest>,
) -> AppResult<Json<UserNotificationPreferenceResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .upsert_user_preference(u.tenant_id, u.id, &req)
            .await?,
    ))
}

async fn list_inbox(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<NotificationInboxItemResponse>>> {
    Ok(Json(s.service.list_inbox(u.tenant_id, u.id).await?))
}

async fn mark_read(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.mark_read(u.tenant_id, u.id, id).await
}

async fn list_rules(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<NotificationRuleResponse>>> {
    Ok(Json(s.service.list_rules(u.tenant_id).await?))
}

async fn create_rule(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Json(req): Json<UpsertNotificationRuleRequest>,
) -> AppResult<Json<NotificationRuleResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_rule(u.tenant_id, &req).await?))
}

async fn delete_rule(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_rule(u.tenant_id, id).await
}

async fn dispatch_event(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Json(req): Json<DispatchNotificationRequest>,
) -> AppResult<Json<serde_json::Value>> {
    req.validate()?;
    let count = s
        .service
        .dispatch(u.tenant_id, &req.event_type, &req.context)
        .await?;
    Ok(Json(serde_json::json!({"fanout": count})))
}
