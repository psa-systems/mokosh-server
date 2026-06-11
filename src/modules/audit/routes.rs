//! Audit log HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::{AuditService, HISTORY_ENTITY_TYPES};
use crate::modules::auth::{RequireAdmin, RequireAuth};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct AuditRouterState {
    pub service: Arc<AuditService>,
}

pub fn audit_routes(service: AuditService) -> Router {
    let state = AuditRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/audit-log", get(list_audit_log))
        .route(
            "/audit-log/entity/{entity_type}/{entity_id}",
            get(list_entity_history),
        )
        .with_state(state)
}

/// Per-record change history. Unlike `/audit-log` this is open to any
/// authenticated tenant member (not just admins) but is tenant-scoped and
/// limited to the whitelisted entity types, so a user can review the edit
/// history of a record they can already see (PMS-182/184/185) without gaining
/// the full tenant audit trail. An unknown entity type is a 404.
async fn list_entity_history(
    State(s): State<AuditRouterState>,
    RequireAuth(u): RequireAuth,
    Path((entity_type, entity_id)): Path<(String, Uuid)>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<EntityHistoryEntry>>> {
    if !HISTORY_ENTITY_TYPES.contains(&entity_type.as_str()) {
        return Err(AppError::NotFound("history".to_string()));
    }
    let (items, total) = s
        .service
        .list_entity_history(u.tenant_id, &entity_type, entity_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn list_audit_log(
    State(s): State<AuditRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Query(filter): Query<AuditLogFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AuditLogEntryResponse>>> {
    filter.validate()?;
    // Super-admins can cross tenants by setting the special X-Tenant-Id
    // header (read by a future middleware); for now everyone reads
    // their own tenant.
    let scope = Some(u.tenant_id);
    let (items, total) = s.service.list(scope, &filter, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}
