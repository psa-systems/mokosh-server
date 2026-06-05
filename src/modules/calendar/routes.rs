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
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

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
        .route(
            "/appointments",
            get(list_appointments).post(create_appointment),
        )
        // PMS-58 range alias: the calendar view fetches the appointment
        // range (recurring series expanded in-memory) from here. Same
        // handler as `GET /appointments`; a bounded `from`+`to` triggers
        // recurrence expansion. Read-only - mutations stay on
        // `/appointments`.
        .route("/calendar/appointments", get(list_appointments))
        .route(
            "/appointments/{id}",
            get(get_appointment)
                .put(update_appointment)
                .delete(delete_appointment),
        )
        // PMS-61 user availability
        .route(
            "/users/{user_id}/availability",
            get(get_user_availability).put(replace_user_availability),
        )
        // PMS-62 time off
        .route("/time-off", get(list_time_off).post(create_time_off))
        .route("/time-off/{id}", get(get_time_off).delete(delete_time_off))
        .route("/time-off/{id}/approval", post(approve_time_off))
        // PMS-63 on-call
        .route("/on-call-schedules", get(list_on_call).post(create_on_call))
        .route(
            "/on-call-schedules/{id}",
            put(update_on_call).delete(delete_on_call),
        )
        .route("/on-call/now", get(on_call_now))
        .with_state(state)
}

/// Mount the dispatch board under `/dispatch` (PMS-58). Shares the same
/// `CalendarService` as the calendar routes; kept as its own router so
/// `create_api_router` can `nest("/dispatch", ...)` exactly where the
/// old self-documenting stub lived.
pub fn dispatch_routes(service: CalendarService) -> Router {
    let state = CalendarRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/", get(dispatch_view))
        .with_state(state)
}

/// `GET /api/v1/dispatch?from=<rfc3339>&to=<rfc3339>&assigned_to_id=<uuid>`
///
/// Aggregated technician dispatch board for a date range: appointments
/// (recurring series expanded), weekly availability, approved time off,
/// and current on-call coverage. `from` and `to` are required because
/// recurring appointments have no natural upper bound.
async fn dispatch_view(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Query(f): Query<DispatchFilter>,
) -> AppResult<Json<DispatchResponse>> {
    f.validate()?;
    let (from, to) = match (f.from, f.to) {
        (Some(from), Some(to)) => (from, to),
        _ => {
            return Err(crate::utils::error::AppError::BadRequest(
                "dispatch view requires both `from` and `to` query parameters".to_string(),
            ))
        }
    };
    if to < from {
        return Err(crate::utils::error::AppError::BadRequest(
            "`to` must be on or after `from`".to_string(),
        ));
    }
    Ok(Json(
        s.service
            .dispatch_view(u.tenant_id, from, to, f.assigned_to_id)
            .await?,
    ))
}

/// `GET /api/v1/calendar/events?from=<rfc3339>&to=<rfc3339>`
async fn list_events(
    RequireAuth(_user): RequireAuth,
    Query(filter): Query<CalendarEventFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<CalendarEvent>>> {
    filter.validate()?;
    Ok(Json(PaginatedResponse::from_params(
        Vec::new(),
        &pagination,
        0,
    )))
}

async fn list_appointments(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Query(f): Query<AppointmentFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AppointmentResponse>>> {
    f.validate()?;
    let (items, total) = s
        .service
        .list_appointments(u.tenant_id, &f, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_appointment(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Json(req): Json<CreateAppointmentRequest>,
) -> AppResult<Json<AppointmentResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_appointment(u.tenant_id, &req).await?))
}

async fn get_appointment(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AppointmentResponse>> {
    Ok(Json(s.service.get_appointment(u.tenant_id, id).await?))
}

async fn update_appointment(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAppointmentRequest>,
) -> AppResult<Json<AppointmentResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_appointment(u.tenant_id, id, &req).await?,
    ))
}

async fn delete_appointment(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_appointment(u.tenant_id, id).await
}

async fn get_user_availability(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Path(user_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<UserAvailabilityResponse>>> {
    let (items, total) = s
        .service
        .get_user_availability(u.tenant_id, user_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn replace_user_availability(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Path(user_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
    Json(req): Json<ReplaceAvailabilityRequest>,
) -> AppResult<Json<PaginatedResponse<UserAvailabilityResponse>>> {
    // Non-admins can only edit their own availability.
    if !u.role.is_admin() && user_id != u.id {
        return Err(crate::utils::error::AppError::Forbidden(
            "Cannot edit another user's availability".to_string(),
        ));
    }
    for w in &req.windows {
        w.validate()?;
    }
    let (items, total) = s
        .service
        .replace_user_availability(u.tenant_id, user_id, &req, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn list_time_off(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Query(f): Query<TimeOffFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TimeOffResponse>>> {
    f.validate()?;
    let (items, total) = s
        .service
        .list_time_off(u.tenant_id, &f, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_time_off(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Json(mut req): Json<CreateTimeOffRequest>,
) -> AppResult<Json<TimeOffResponse>> {
    if !u.role.is_admin() && req.user_id != u.id {
        req.user_id = u.id;
    }
    req.validate()?;
    Ok(Json(s.service.create_time_off(u.tenant_id, &req).await?))
}

async fn get_time_off(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<TimeOffResponse>> {
    Ok(Json(s.service.get_time_off(u.tenant_id, id).await?))
}

async fn approve_time_off(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Path(id): Path<Uuid>,
    Json(req): Json<ApproveTimeOffRequest>,
) -> AppResult<Json<TimeOffResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .approve_time_off(u.tenant_id, id, u.id, &req.status)
            .await?,
    ))
}

async fn delete_time_off(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_time_off(u.tenant_id, id).await
}

async fn list_on_call(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<OnCallScheduleResponse>>> {
    let (items, total) = s
        .service
        .list_on_call_schedules(u.tenant_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_on_call(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Json(req): Json<UpsertOnCallScheduleRequest>,
) -> AppResult<Json<OnCallScheduleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_on_call_schedule(u.tenant_id, &req).await?,
    ))
}

async fn update_on_call(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertOnCallScheduleRequest>,
) -> AppResult<Json<OnCallScheduleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_on_call_schedule(u.tenant_id, id, &req)
            .await?,
    ))
}

async fn delete_on_call(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_on_call_schedule(u.tenant_id, id).await
}

async fn on_call_now(
    State(s): State<CalendarRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<OnCallNowResponse>>> {
    Ok(Json(s.service.on_call_now(u.tenant_id).await?))
}
