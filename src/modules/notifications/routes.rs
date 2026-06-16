//! Notifications HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::NotificationsService;
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

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
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<NotificationChannelResponse>>> {
    let (items, total) = s.service.list_channels(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_channel(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertNotificationChannelRequest>,
) -> AppResult<Json<NotificationChannelResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_channel(u.tenant(), &req, &ctx).await?,
    ))
}

async fn delete_channel(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_channel(u.tenant(), id).await
}

async fn list_templates(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<NotificationTemplateResponse>>> {
    let (items, total) = s.service.list_templates(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_template(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertNotificationTemplateRequest>,
) -> AppResult<Json<NotificationTemplateResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_template(u.tenant(), &req, &ctx).await?,
    ))
}

async fn delete_template(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_template(u.tenant(), id).await
}

async fn list_user_prefs(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<UserNotificationPreferenceResponse>>> {
    let (items, total) = s
        .service
        .list_user_preferences(u.tenant(), u.id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn upsert_user_pref(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Json(req): Json<UpsertUserNotificationPreferenceRequest>,
) -> AppResult<Json<UserNotificationPreferenceResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .upsert_user_preference(u.tenant(), u.id, &req)
            .await?,
    ))
}

async fn list_inbox(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<NotificationInboxItemResponse>>> {
    let (items, total) = s.service.list_inbox(u.tenant(), u.id, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn mark_read(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.mark_read(u.tenant(), u.id, id).await
}

async fn list_rules(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<NotificationRuleResponse>>> {
    let (items, total) = s.service.list_rules(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_rule(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertNotificationRuleRequest>,
) -> AppResult<Json<NotificationRuleResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_rule(u.tenant(), &req, &ctx).await?))
}

async fn delete_rule(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_rule(u.tenant(), id).await
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
        .dispatch(u.tenant(), &req.event_type, &req.context)
        .await?;
    Ok(Json(serde_json::json!({"fanout": count})))
}
