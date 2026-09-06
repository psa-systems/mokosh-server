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
use crate::db::Database;
use crate::modules::auth::{
    CallerContext, RequireAdmin, RequireAuth, RequireCallerContext, TenantScoped,
};
use crate::modules::contact_portal::capabilities as caps;
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
            axum::routing::put(update_channel).delete(delete_channel),
        )
        // PMS-88 templates
        .route(
            "/notification-templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/notification-templates/{id}",
            axum::routing::put(update_template).delete(delete_template),
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
            axum::routing::put(update_rule).delete(delete_rule),
        )
        // PMS-92 dispatcher (manual trigger; the real worker calls
        // NotificationsService::dispatch directly)
        .route("/notifications/dispatch", post(dispatch_event))
        // PMS-808 preview: render what dispatch would send, send nothing
        .route("/notifications/preview", post(preview_event))
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

async fn update_channel(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertNotificationChannelRequest>,
) -> AppResult<Json<NotificationChannelResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_channel(u.tenant(), id, &req, &ctx).await?,
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

async fn update_template(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertNotificationTemplateRequest>,
) -> AppResult<Json<NotificationTemplateResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_template(u.tenant(), id, &req, &ctx)
            .await?,
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

/// PMS-1083: dual-plane. A staff user reads the rows against its
/// `user_id`, a contact holding `notifications:read` (DB-loaded per
/// request) the rows against its `contact_id`; the two never share a
/// row, so neither arm can see the other's inbox. Same envelope and
/// item shape on both, which is what the SPA's bell reads.
async fn list_inbox(
    State(s): State<NotificationsRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<NotificationInboxItemResponse>>> {
    let tenant = caller.tenant();
    let (items, total) = match &caller {
        CallerContext::Staff(auth) => {
            let user = staff_user(auth)?;
            s.service.list_inbox(tenant, user.id, &pagination).await?
        }
        CallerContext::Contact(session) => {
            caller
                .require_capability(caps::NOTIFICATIONS_READ, &db)
                .await?;
            s.service
                .list_inbox_for_contact(tenant, session.id, &pagination)
                .await?
        }
    };
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

/// PMS-1083: dual-plane, the same split as `list_inbox`. A row that is
/// not the caller's own is a 404 on both arms.
async fn mark_read(
    State(s): State<NotificationsRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => {
            let user = staff_user(auth)?;
            s.service.mark_read(tenant, user.id, id).await
        }
        CallerContext::Contact(session) => {
            caller
                .require_capability(caps::NOTIFICATIONS_READ, &db)
                .await?;
            s.service
                .mark_read_for_contact(tenant, session.id, id)
                .await
        }
    }
}

/// The staff arm of a dual-plane inbox read keeps the surface
/// `RequireAuth` gave it: an authenticated staff user, else 401.
fn staff_user(
    auth: &crate::modules::auth::AuthState,
) -> AppResult<&crate::modules::auth::CurrentUser> {
    auth.user
        .as_ref()
        .ok_or(crate::utils::error::AppError::Unauthorized)
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

async fn update_rule(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertNotificationRuleRequest>,
) -> AppResult<Json<NotificationRuleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_rule(u.tenant(), id, &req, &ctx).await?,
    ))
}

async fn delete_rule(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_rule(u.tenant(), id).await
}

/// PMS-808: what would this event mail, for this context? Nothing is
/// queued, minted or sent, so this sits behind the module's read-side
/// `RequireAuth` rather than the admin gate the write paths use: it
/// exposes the caller's own tenant's templates and rule recipients,
/// which `GET /notification-templates` and `GET /notification-rules`
/// already return to any authenticated user.
async fn preview_event(
    State(s): State<NotificationsRouterState>,
    RequireAuth(u): RequireAuth,
    Json(req): Json<DispatchNotificationRequest>,
) -> AppResult<Json<Vec<NotificationPreviewResponse>>> {
    req.validate()?;
    Ok(Json(
        s.service
            .preview(u.tenant(), &req.event_type, &req.context)
            .await?,
    ))
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
