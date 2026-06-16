//! SLA HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::SlaService;
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct SlaRouterState {
    pub service: Arc<SlaService>,
}

pub fn sla_routes(service: SlaService) -> Router {
    let state = SlaRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // PMS-108 policies
        .route("/sla/policies", get(list_policies).post(create_policy))
        .route(
            "/sla/policies/{id}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        // PMS-109 targets
        .route(
            "/sla/policies/{id}/targets",
            get(list_targets).post(upsert_target),
        )
        .route("/sla/targets/{id}", axum::routing::delete(delete_target))
        // PMS-110 business hours
        .route(
            "/sla/business-hours",
            get(list_business_hours).post(create_business_hours),
        )
        .route(
            "/sla/business-hours/{id}",
            put(update_business_hours).delete(delete_business_hours),
        )
        // PMS-111 holiday calendars
        .route(
            "/sla/holiday-calendars",
            get(list_holiday_calendars).post(create_holiday_calendar),
        )
        .route(
            "/sla/holiday-calendars/{id}",
            put(update_holiday_calendar).delete(delete_holiday_calendar),
        )
        // PMS-112 evaluator (manual trigger; ticket service calls
        // SlaService::evaluate_for_ticket on create/status change in a
        // follow-up wire-up commit)
        .route("/sla/tickets/{id}/evaluate", post(evaluate_for_ticket))
        .with_state(state)
}

async fn list_policies(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<SlaPolicyResponse>>> {
    let (items, total) = s.service.list_policies(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_policy(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertSlaPolicyRequest>,
) -> AppResult<Json<SlaPolicyResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_policy(u.tenant(), &req, &ctx).await?))
}

async fn get_policy(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<SlaPolicyResponse>> {
    Ok(Json(s.service.get_policy(u.tenant(), id).await?))
}

async fn update_policy(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertSlaPolicyRequest>,
) -> AppResult<Json<SlaPolicyResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_policy(u.tenant(), id, &req).await?))
}

async fn delete_policy(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_policy(u.tenant(), id).await
}

async fn list_targets(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<SlaTargetResponse>>> {
    let (items, total) = s.service.list_targets(u.tenant(), id, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn upsert_target(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertSlaTargetRequest>,
) -> AppResult<Json<SlaTargetResponse>> {
    req.validate()?;
    Ok(Json(s.service.upsert_target(u.tenant(), id, &req).await?))
}

async fn delete_target(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_target(u.tenant(), id).await
}

async fn list_business_hours(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<BusinessHoursResponse>>> {
    let (items, total) = s
        .service
        .list_business_hours(u.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_business_hours(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertBusinessHoursRequest>,
) -> AppResult<Json<BusinessHoursResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .create_business_hours(u.tenant(), &req, &ctx)
            .await?,
    ))
}

async fn update_business_hours(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertBusinessHoursRequest>,
) -> AppResult<Json<BusinessHoursResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_business_hours(u.tenant(), id, &req)
            .await?,
    ))
}

async fn delete_business_hours(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_business_hours(u.tenant(), id).await
}

async fn list_holiday_calendars(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<HolidayCalendarResponse>>> {
    let (items, total) = s
        .service
        .list_holiday_calendars(u.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_holiday_calendar(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertHolidayCalendarRequest>,
) -> AppResult<Json<HolidayCalendarResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .create_holiday_calendar(u.tenant(), &req, &ctx)
            .await?,
    ))
}

async fn update_holiday_calendar(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertHolidayCalendarRequest>,
) -> AppResult<Json<HolidayCalendarResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_holiday_calendar(u.tenant(), id, &req)
            .await?,
    ))
}

async fn delete_holiday_calendar(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_holiday_calendar(u.tenant(), id).await
}

async fn evaluate_for_ticket(
    State(s): State<SlaRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.evaluate_for_ticket(u.tenant(), id).await
}
