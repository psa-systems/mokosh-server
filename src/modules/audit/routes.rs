//! Audit log HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use validator::Validate;

use super::models::*;
use super::service::AuditService;
use crate::modules::auth::{RequireAdmin, RequireAuth};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct AuditRouterState {
    pub service: Arc<AuditService>,
}

pub fn audit_routes(service: AuditService) -> Router {
    let state = AuditRouterState { service: Arc::new(service) };
    Router::new()
        .route("/audit-log", get(list_audit_log))
        .with_state(state)
}

async fn list_audit_log(
    State(s): State<AuditRouterState>, RequireAuth(u): RequireAuth, _a: RequireAdmin,
    Query(filter): Query<AuditLogFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AuditLogEntryResponse>>> {
    filter.validate()?;
    // Super-admins can cross tenants by setting the special X-Tenant-Id
    // header (read by a future middleware); for now everyone reads
    // their own tenant.
    let scope = Some(u.tenant_id);
    let (items, total) = s.service.list(scope, &filter, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(items, &pagination, total)))
}
