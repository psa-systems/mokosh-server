//! MAPPS-298: HTTP route for cross-entity search.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;

use super::service::{SearchResponse, SearchService};
use crate::modules::auth::RequireAuth;
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct SearchRouterState {
    pub service: Arc<SearchService>,
}

pub fn search_routes(service: SearchService) -> Router {
    let state = SearchRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/search", get(search))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    /// Free-text query. Trimmed; empty / whitespace returns an empty
    /// envelope without touching the database. Capped at 200 chars to
    /// keep ILIKE plans bounded (mirrors `CompanyFilter::q`,
    /// `ContactFilter::q`, `TicketFilter::q`).
    #[serde(default)]
    q: String,
}

/// `GET /api/v1/search?q=<text>` - cross-entity tenant-scoped search.
/// Open to any authenticated tenant member; the service tenant-scopes
/// every query so users only see their own tenant's data. Per-entity
/// permission boundaries (e.g. RequireFinance on contracts) are
/// intentionally NOT applied here - the search hits are the user's own
/// tenant data and are read-only previews; clicking through goes to
/// the entity's normal detail page which enforces its own access.
async fn search(
    State(s): State<SearchRouterState>,
    RequireAuth(u): RequireAuth,
    Query(q): Query<SearchQuery>,
) -> AppResult<Json<SearchResponse>> {
    // Cap the query length so a pathological client cannot force a
    // 10MB ILIKE pattern. 200 chars matches the other `q` caps across
    // the API.
    let q_trimmed = if q.q.chars().count() > 200 {
        q.q.chars().take(200).collect::<String>()
    } else {
        q.q
    };
    let response = s.service.search(u.tenant_id, &q_trimmed).await?;
    Ok(Json(response))
}
