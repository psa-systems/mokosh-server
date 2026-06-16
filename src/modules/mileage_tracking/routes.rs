//! Mileage-tracking HTTP routes (PMS-315). Shape mirrors the time-entry CRUD
//! endpoints; gated by the time-tracking module (`RequireTimeTracking`).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::MileageTrackingService;
use crate::modules::auth::{RequireTimeTracking, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct MileageTrackingRouterState {
    pub service: Arc<MileageTrackingService>,
}

pub fn mileage_tracking_routes(service: MileageTrackingService) -> Router {
    let state = MileageTrackingRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route(
            "/mileage-entries",
            get(list_mileage_entries).post(create_mileage_entry),
        )
        .route(
            "/mileage-entries/{id}",
            get(get_mileage_entry)
                .put(update_mileage_entry)
                .delete(delete_mileage_entry),
        )
        .with_state(state)
}

async fn list_mileage_entries(
    State(state): State<MileageTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Query(filter): Query<MileageEntryFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<MileageEntryResponse>>> {
    filter.validate()?;
    let (items, total) = state
        .service
        .list_mileage_entries(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_mileage_entry(
    State(state): State<MileageTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    ctx: crate::modules::audit::AuditCtx,
    Json(mut request): Json<CreateMileageEntryRequest>,
) -> AppResult<Json<MileageEntryResponse>> {
    // Non-admins can only log mileage for themselves.
    if !user.role.is_admin() && request.user_id != user.id {
        request.user_id = user.id;
    }
    request.validate()?;
    Ok(Json(
        state
            .service
            .create_mileage_entry(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn get_mileage_entry(
    State(state): State<MileageTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Path(id): Path<Uuid>,
) -> AppResult<Json<MileageEntryResponse>> {
    Ok(Json(
        state.service.get_mileage_entry(user.tenant(), id).await?,
    ))
}

async fn update_mileage_entry(
    State(state): State<MileageTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateMileageEntryRequest>,
) -> AppResult<Json<MileageEntryResponse>> {
    request.validate()?;
    // A non-admin can only edit their own entry; an unknown id 404s first.
    let existing = state.service.get_mileage_entry(user.tenant(), id).await?;
    if !user.role.is_admin() && existing.user_id != user.id {
        return Err(crate::utils::error::AppError::Forbidden(
            "Cannot edit another user's mileage entry".to_string(),
        ));
    }
    Ok(Json(
        state
            .service
            .update_mileage_entry(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_mileage_entry(
    State(state): State<MileageTrackingRouterState>,
    RequireTimeTracking { user, .. }: RequireTimeTracking,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    // A non-admin can only delete their own entry; an unknown id 404s first.
    let existing = state.service.get_mileage_entry(user.tenant(), id).await?;
    if !user.role.is_admin() && existing.user_id != user.id {
        return Err(crate::utils::error::AppError::Forbidden(
            "Cannot delete another user's mileage entry".to_string(),
        ));
    }
    state.service.delete_mileage_entry(user.tenant(), id).await
}
