//! PMS-800: `GET /api/v1/companies/{company_id}/documentation` returns
//! the aggregate view of a client's documentation. Gated by
//! `RequireAssets` so a non-admin technician working a ticket can read
//! it (same posture as the asset list and credential summary the
//! aggregate composes); the audited reveal path is where secret values
//! come from.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::get,
    Router,
};
use uuid::Uuid;

use super::service::{CompanyDocumentation, DocumentationService};
use crate::modules::auth::{RequireAssets, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::json::Json;

#[derive(Clone)]
pub struct DocumentationRouterState {
    pub service: Arc<DocumentationService>,
}

pub fn documentation_routes(service: DocumentationService) -> Router {
    let state = DocumentationRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/{company_id}/documentation", get(company_documentation))
        .with_state(state)
}

async fn company_documentation(
    State(state): State<DocumentationRouterState>,
    RequireAssets { user, .. }: RequireAssets,
    Path(company_id): Path<Uuid>,
) -> AppResult<Json<CompanyDocumentation>> {
    Ok(Json(
        state
            .service
            .documentation_for_company(user.tenant(), company_id)
            .await?,
    ))
}
