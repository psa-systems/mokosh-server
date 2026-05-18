//! Calendar API routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::CalendarService;
use super::{CalendarEvent, CalendarEventFilter};
use crate::modules::auth::{RequireAuth, RequireManager};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct CalendarRouterState {
    pub service: Arc<CalendarService>,
}

/// Mount calendar endpoints under `/api/v1` (the parent router uses
/// `merge`). The pre-existing `/calendar/events` placeholder stays so
/// existing clients keep working.
pub fn calendar_routes(service: CalendarService) -> Router {
    let state = CalendarRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // Legacy events surface
        .route("/calendar/events", get(list_events))
        // PMS-60 appointments
        .route("/appointments", get(list_appointments).post(create_appointment))
        .route(
            "/appointments/{id}",
            get(get_appointment).put(update_appointment).delete(delete_appointment),
        )
        // PMS-61 user availability
        .route(
            "/users/{user_id}/availability",
            get(get_user_availability).put(replace_user_availability),
        )
        // PMS-62 time off
        .route("/time-off", get(list_time_off).post(create_time_off))
        .route(
            "/time-off/{id}",
            get(get_time_off).delete(delete_time_off),
        )
        .route("/time-off/{id}/approval", post(approve_time_off))
        // PMS-63 on-call
        .route(
            "/on-call-schedules",
            get(list_on_call).post(create_on_call),
        )
        .route(
            "/on-call-schedules/{id}",
            put(update_on_call).delete(delete_on_call),
        )
        .route("/on-call/now", get(on_call_now))
        .with_state(state)
}

/// `GET /api/v1/calendar/events?from=<rfc3339>&to=<rfc3339>`
async fn list_events(
    RequireAuth(_user): RequireAuth,
    Query(_filter): Query<CalendarEventFilter>,
) -> AppResult<Json<Vec<CalendarEvent>>> {
    Ok(Json(Vec::new()))
}

async fn list_appointments(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth,
    Query(f): Query<AppointmentFilter>,
) -> AppResult<Json<Vec<AppointmentResponse>>> {
    f.validate()?;
    Ok(Json(s.service.list_appointments(u.tenant_id, &f).await?))
}

async fn create_appointment(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth,
    Json(req): Json<CreateAppointmentRequest>,
) -> AppResult<Json<AppointmentResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_appointment(u.tenant_id, &req).await?))
}

async fn get_appointment(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, Path(id): Path<Uuid>,
) -> AppResult<Json<AppointmentResponse>> {
    Ok(Json(s.service.get_appointment(u.tenant_id, id).await?))
}

async fn update_appointment(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>, Json(req): Json<UpdateAppointmentRequest>,
) -> AppResult<Json<AppointmentResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_appointment(u.tenant_id, id, &req).await?))
}

async fn delete_appointment(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_appointment(u.tenant_id, id).await }

async fn get_user_availability(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, Path(user_id): Path<Uuid>,
) -> AppResult<Json<Vec<UserAvailabilityResponse>>> {
    Ok(Json(s.service.get_user_availability(u.tenant_id, user_id).await?))
}

async fn replace_user_availability(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth,
    Path(user_id): Path<Uuid>, Json(req): Json<ReplaceAvailabilityRequest>,
) -> AppResult<Json<Vec<UserAvailabilityResponse>>> {
    // Non-admins can only edit their own availability.
    if !u.role.is_admin() && user_id != u.id {
        return Err(crate::utils::error::AppError::Forbidden(
            "Cannot edit another user's availability".to_string(),
        ));
    }
    for w in &req.windows { w.validate()?; }
    Ok(Json(s.service.replace_user_availability(u.tenant_id, user_id, &req).await?))
}

async fn list_time_off(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth,
    Query(f): Query<TimeOffFilter>,
) -> AppResult<Json<Vec<TimeOffResponse>>> {
    f.validate()?;
    Ok(Json(s.service.list_time_off(u.tenant_id, &f).await?))
}

async fn create_time_off(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth,
    Json(mut req): Json<CreateTimeOffRequest>,
) -> AppResult<Json<TimeOffResponse>> {
    if !u.role.is_admin() && req.user_id != u.id {
        req.user_id = u.id;
    }
    req.validate()?;
    Ok(Json(s.service.create_time_off(u.tenant_id, &req).await?))
}

async fn get_time_off(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, Path(id): Path<Uuid>,
) -> AppResult<Json<TimeOffResponse>> {
    Ok(Json(s.service.get_time_off(u.tenant_id, id).await?))
}

async fn approve_time_off(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, _m: RequireManager,
    Path(id): Path<Uuid>, Json(req): Json<ApproveTimeOffRequest>,
) -> AppResult<Json<TimeOffResponse>> {
    req.validate()?;
    Ok(Json(s.service.approve_time_off(u.tenant_id, id, u.id, &req.status).await?))
}

async fn delete_time_off(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_time_off(u.tenant_id, id).await }

async fn list_on_call(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<OnCallScheduleResponse>>> {
    Ok(Json(s.service.list_on_call_schedules(u.tenant_id).await?))
}

async fn create_on_call(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, _m: RequireManager,
    Json(req): Json<UpsertOnCallScheduleRequest>,
) -> AppResult<Json<OnCallScheduleResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_on_call_schedule(u.tenant_id, &req).await?))
}

async fn update_on_call(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, _m: RequireManager,
    Path(id): Path<Uuid>, Json(req): Json<UpsertOnCallScheduleRequest>,
) -> AppResult<Json<OnCallScheduleResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_on_call_schedule(u.tenant_id, id, &req).await?))
}

async fn delete_on_call(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth, _m: RequireManager,
    Path(id): Path<Uuid>,
) -> AppResult<()> { s.service.delete_on_call_schedule(u.tenant_id, id).await }

async fn on_call_now(
    State(s): State<CalendarRouterState>, RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<OnCallNowResponse>>> {
    Ok(Json(s.service.on_call_now(u.tenant_id).await?))
}
