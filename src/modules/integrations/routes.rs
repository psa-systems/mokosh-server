//! HTTP surface for the integrations page (PMS-1310).
//!
//! Called by Settings > Integrations in mokosh-apps (MAPPS-971,
//! `src/pages/settings_integrations.rs`), which is the client half PMS-1310's
//! last acceptance criterion asked for. This module carried a dated exemption
//! from `check-route-consumers` until that page existed; it exists, so the
//! exemption is gone rather than re-dated, and the guard now holds these routes
//! to a real caller.
//!
//! Mounted at `/api/v1/integrations` by `create_api_router`, so the paths here
//! are relative to that prefix.
//!
//! # One route, because the per-provider four served nobody (PMS-1571)
//!
//! This module used to mount `GET`/`PUT /integrations/{provider}` and
//! `POST /integrations/{provider}/connect` and `/disconnect` beside the list.
//! They were reachable by URL and answered 404 for every provider in the
//! registry, because the only credential home this surface can connect is
//! [`CredentialHome::Integration`](super::registry::CredentialHome::Integration),
//! the one whose credential arrives in the connect request, and no entry
//! carries it. Each provider's credential belongs to another surface for its
//! own documented reason: the payment gateways to their credential form, the
//! two invoice issuers to their OAuth consent round trips, the three contact
//! sources to contact sync.
//!
//! MAPPS-1153 left them mounted on the argument that the registry is the one
//! place that decides, so a provider that did take its credential here would
//! be served again without a route being rebuilt. What that produced instead
//! was four routes nobody could reach and three call sites in the SPA that
//! never rendered, since `settings_integrations.rs` reads the same
//! `configurable_here` flag to decide whether to draw the controls at all.
//!
//! The registry still decides, and
//! [`tests::an_integration_home_provider_needs_the_per_provider_routes_back`](super::registry)
//! is what makes that mean something: it fails the day an entry takes the
//! `Integration` home with these routes absent, and it fails today if they
//! come back while no entry does. Restoring them is adding the four
//! `.route(...)` lines back with their handlers, which the service methods
//! and request DTOs are still here for.
//!
//! The one remaining handler takes `RequireAdmin`: what an organization has
//! delegated to a third party is not a technician's read. There is no module
//! gate on top - integrations are how a tenant turns capabilities ON, so
//! gating the page behind a module a tenant has not enabled would hide the
//! switch behind itself.

use std::sync::Arc;

use axum::{extract::State, routing::get, Router};

use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::json::Json;

use super::models::*;
use super::service::IntegrationsService;

#[derive(Clone)]
pub struct IntegrationsRouterState {
    pub service: Arc<IntegrationsService>,
}

// SPEC-15.1501: list is the only mounted route
pub fn integration_routes(service: IntegrationsService) -> Router {
    let state = IntegrationsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/integrations", get(list_integrations))
        .with_state(state)
}

// SPEC-15.1500: admin-only list
async fn list_integrations(
    State(state): State<IntegrationsRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<IntegrationResponse>>> {
    Ok(Json(state.service.list(user.tenant()).await?))
}
