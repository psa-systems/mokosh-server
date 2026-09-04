//! Time-tracking HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use chrono::NaiveDate;
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::TimeTrackingService;
use crate::modules::auth::{
    RequireAdmin, RequireManager, RequireTimeTracking, RequireTimesheets, TenantScoped,
};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct TimeTrackingRouterState {
    pub service: Arc<TimeTrackingService>,
}

pub fn time_tracking_routes(service: TimeTrackingService) -> Router {
    let state = TimeTrackingRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // PMS-50 work types
        .route("/work-types", get(list_work_types).post(create_work_type))
        .route(
            "/work-types/{id}",
            put(update_work_type).delete(delete_work_type),
        )
        // PMS-44 / PMS-45 time entries
        .route(
            "/time-entries",
            get(list_time_entries).post(create_time_entry),
        )
        .route(
            "/time-entries/{id}",
            get(get_time_entry)
                .put(update_time_entry)
                .delete(delete_time_entry),
        )
        // PMS-46 / PMS-47 timesheets
        .route("/timesheets", get(list_timesheets))
        .route(
            "/timesheets/{user_id}/{week_start}/submit",
            post(submit_timesheet),
        )
        .route(
            "/timesheets/{user_id}/{week_start}/withdraw",
            post(withdraw_timesheet),
        )
        .route(
            "/timesheets/{user_id}/{week_start}/approve",
            post(approve_timesheet),
        )
        .route(
            "/timesheets/{user_id}/{week_start}/reject",
            post(reject_timesheet),
        )
        // PMS-48 active timers
        .route("/timers/active", get(list_active_timers))
        .route("/timers/start", post(start_timer))
        .route("/timers/{id}/stop", post(stop_timer))
        // PMS-950 the work day: clock in and out, breaks, and the day view.
        // Every one of these carries the timesheets gate as well.
        .route("/workday", get(work_day))
        .route("/workday/clock-in", post(clock_in))
        .route("/workday/clock-out", post(clock_out))
        .route("/workday/break/start", post(start_break))
        .route("/workday/break/end", post(end_break))
        // PMS-49 time rounding rules
        .route(
            "/time-rounding-rules",
            get(list_rounding_rules).post(create_rounding_rule),
        )
        .route(
            "/time-rounding-rules/{id}",
            put(update_rounding_rule).delete(delete_rounding_rule),
        )
        .with_state(state)
}

// ============================================================================
// Work types
// ============================================================================

async fn list_work_types(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<WorkTypeResponse>>> {
    let (items, total) = state
        .service
        .list_work_types(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_work_type(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertWorkTypeRequest>,
) -> AppResult<Json<WorkTypeResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .service
            .create_work_type(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn update_work_type(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertWorkTypeRequest>,
) -> AppResult<Json<WorkTypeResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .service
            .update_work_type(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_work_type(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state.service.delete_work_type(user.tenant(), id).await
}

// ============================================================================
// Time entries
// ============================================================================

async fn list_time_entries(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Query(filter): Query<TimeEntryFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TimeEntryResponse>>> {
    filter.validate()?;
    let (items, total) = state
        .service
        .list_time_entries(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_time_entry(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    ctx: crate::modules::audit::AuditCtx,
    Json(mut request): Json<CreateTimeEntryRequest>,
) -> AppResult<Json<TimeEntryResponse>> {
    // Non-admins can only log time for themselves.
    if !user.role.is_admin() && request.user_id != user.id {
        request.user_id = user.id;
    }
    request.validate()?;
    Ok(Json(
        state
            .service
            .create_time_entry(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn get_time_entry(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Path(id): Path<Uuid>,
) -> AppResult<Json<TimeEntryResponse>> {
    Ok(Json(state.service.get_time_entry(user.tenant(), id).await?))
}

async fn update_time_entry(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateTimeEntryRequest>,
) -> AppResult<Json<TimeEntryResponse>> {
    request.validate()?;
    // A non-admin can only edit their own entry; an unknown id 404s first.
    let existing = state.service.get_time_entry(user.tenant(), id).await?;
    if !user.role.is_admin() && existing.user_id != user.id {
        return Err(crate::utils::error::AppError::Forbidden(
            "Cannot edit another user's time entry".to_string(),
        ));
    }
    Ok(Json(
        state
            .service
            .update_time_entry(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_time_entry(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    // A non-admin can only delete their own entry; an unknown id 404s first.
    let existing = state.service.get_time_entry(user.tenant(), id).await?;
    if !user.role.is_admin() && existing.user_id != user.id {
        return Err(crate::utils::error::AppError::Forbidden(
            "Cannot delete another user's time entry".to_string(),
        ));
    }
    state.service.delete_time_entry(user.tenant(), id).await
}

// ============================================================================
// Timesheets
// ============================================================================

async fn list_timesheets(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    // PMS-943: the feature gate, on top of the module gate above. A tenant
    // with timesheets off gets 404 here, which is what the extractor returns
    // so a disabled feature reads exactly like a route that does not exist.
    _timesheets: RequireTimesheets,
    Query(filter): Query<TimesheetFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TimesheetSummaryResponse>>> {
    filter.validate()?;
    let (items, total) = state
        .service
        .list_timesheets(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn submit_timesheet(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    // PMS-943: the feature gate, on top of the module gate above. A tenant
    // with timesheets off gets 404 here, which is what the extractor returns
    // so a disabled feature reads exactly like a route that does not exist.
    _timesheets: RequireTimesheets,
    Path((user_id, week_start)): Path<(Uuid, NaiveDate)>,
) -> AppResult<Json<TimesheetSummaryResponse>> {
    if !user.role.is_admin() && user_id != user.id {
        return Err(crate::utils::error::AppError::Forbidden(
            "Cannot submit another user's timesheet".to_string(),
        ));
    }
    Ok(Json(
        state
            .service
            .submit_timesheet(user.tenant(), user_id, week_start)
            .await?,
    ))
}

async fn withdraw_timesheet(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    // PMS-943: the feature gate, on top of the module gate above. A tenant
    // with timesheets off gets 404 here, which is what the extractor returns
    // so a disabled feature reads exactly like a route that does not exist.
    _timesheets: RequireTimesheets,
    Path((user_id, week_start)): Path<(Uuid, NaiveDate)>,
) -> AppResult<Json<TimesheetSummaryResponse>> {
    if !user.role.is_admin() && user_id != user.id {
        return Err(crate::utils::error::AppError::Forbidden(
            "Cannot withdraw another user's timesheet".to_string(),
        ));
    }
    Ok(Json(
        state
            .service
            .withdraw_timesheet(user.tenant(), user_id, week_start)
            .await?,
    ))
}

async fn approve_timesheet(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    // PMS-943: the feature gate, on top of the module gate above. A tenant
    // with timesheets off gets 404 here, which is what the extractor returns
    // so a disabled feature reads exactly like a route that does not exist.
    _timesheets: RequireTimesheets,
    _mgr: RequireManager,
    Path((user_id, week_start)): Path<(Uuid, NaiveDate)>,
) -> AppResult<Json<TimesheetSummaryResponse>> {
    Ok(Json(
        state
            .service
            .approve_timesheet(user.tenant(), user.id, user_id, week_start)
            .await?,
    ))
}

async fn reject_timesheet(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    // PMS-943: the feature gate, on top of the module gate above. A tenant
    // with timesheets off gets 404 here, which is what the extractor returns
    // so a disabled feature reads exactly like a route that does not exist.
    _timesheets: RequireTimesheets,
    _mgr: RequireManager,
    Path((user_id, week_start)): Path<(Uuid, NaiveDate)>,
    Json(request): Json<RejectTimesheetRequest>,
) -> AppResult<Json<TimesheetSummaryResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .service
            .reject_timesheet(user.tenant(), user.id, user_id, week_start, &request.reason)
            .await?,
    ))
}

// ============================================================================
// Active timers
// ============================================================================

#[derive(serde::Deserialize)]
struct ActiveTimersQuery {
    user_id: Option<Uuid>,
}

async fn list_active_timers(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Query(q): Query<ActiveTimersQuery>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ActiveTimerResponse>>> {
    // Non-admins always see only their own timer.
    let user_filter = if user.role.is_admin() {
        q.user_id
    } else {
        Some(user.id)
    };
    let (items, total) = state
        .service
        .list_active_timers(user.tenant(), user_filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn start_timer(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Json(request): Json<StartTimerRequest>,
) -> AppResult<Json<ActiveTimerResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .service
            .start_timer(user.tenant(), user.id, &request)
            .await?,
    ))
}

async fn stop_timer(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Path(id): Path<Uuid>,
) -> AppResult<Json<TimeEntryResponse>> {
    Ok(Json(state.service.stop_timer(user.tenant(), id).await?))
}

// ============================================================================
// PMS-950 work day
// ============================================================================

/// The clock is always the caller's own. There is no body to speak of: a
/// missing one is the same as `{}`, so a client may POST with no content type.
async fn clock_in(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    // PMS-943: the feature gate, on top of the module gate above. A tenant
    // with timesheets off gets 404 here, which is what the extractor returns
    // so a disabled feature reads exactly like a route that does not exist.
    _timesheets: RequireTimesheets,
    request: Option<Json<ClockInRequest>>,
) -> AppResult<Json<WorkDaySegmentResponse>> {
    let request = request.map(|Json(r)| r).unwrap_or_default();
    request.validate()?;
    Ok(Json(
        state
            .service
            .clock_in(user.tenant(), user.id, &request)
            .await?,
    ))
}

async fn clock_out(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _timesheets: RequireTimesheets,
) -> AppResult<Json<WorkDaySegmentResponse>> {
    Ok(Json(state.service.clock_out(user.tenant(), user.id).await?))
}

async fn start_break(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _timesheets: RequireTimesheets,
) -> AppResult<Json<WorkDaySegmentResponse>> {
    Ok(Json(
        state.service.start_break(user.tenant(), user.id).await?,
    ))
}

async fn end_break(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _timesheets: RequireTimesheets,
) -> AppResult<Json<WorkDaySegmentResponse>> {
    Ok(Json(state.service.end_break(user.tenant(), user.id).await?))
}

/// A non-admin sees their own day; an admin may name whose. The same rule as
/// the active-timer list and the timesheet submit above.
async fn work_day(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _timesheets: RequireTimesheets,
    Query(query): Query<WorkDayQuery>,
) -> AppResult<Json<WorkDayResponse>> {
    query.validate()?;
    let user_id = match query.user_id {
        Some(other) if user.role.is_admin() => other,
        Some(other) if other != user.id => {
            return Err(crate::utils::error::AppError::Forbidden(
                "Cannot view another user's day".to_string(),
            ));
        }
        _ => user.id,
    };
    Ok(Json(
        state
            .service
            .work_day(user.tenant(), user_id, query.date)
            .await?,
    ))
}

// ============================================================================
// Rounding rules
// ============================================================================

async fn list_rounding_rules(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TimeRoundingRuleResponse>>> {
    let (items, total) = state
        .service
        .list_rounding_rules(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_rounding_rule(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertTimeRoundingRuleRequest>,
) -> AppResult<Json<TimeRoundingRuleResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .service
            .create_rounding_rule(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn update_rounding_rule(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertTimeRoundingRuleRequest>,
) -> AppResult<Json<TimeRoundingRuleResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .service
            .update_rounding_rule(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_rounding_rule(
    State(state): State<TimeTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state.service.delete_rounding_rule(user.tenant(), id).await
}
