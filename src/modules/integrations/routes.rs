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
//! are relative to that prefix. The literal `/{provider}` segment is parsed
//! against the integration enum; a bare string that is not a provider gets a
//! 404 at [`parse_provider`].
//!
//! Every handler takes `RequireAdmin`. Deciding that Xero issues this MSP's
//! invoices is not a technician's call, and `connect` accepts a credential, so
//! the gate is the same one the rest of Settings carries. There is no module
//! gate on top: integrations are how a tenant turns capabilities ON, so gating
//! the page behind a module a tenant has not enabled would hide the switch
//! behind itself.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{get, post, put},
    Router,
};
use validator::Validate;

use crate::modules::audit::AuditCtx;
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::{AppError, AppResult};
use crate::utils::json::Json;

use super::models::*;
use super::registry;
use super::service::IntegrationsService;

#[derive(Clone)]
pub struct IntegrationsRouterState {
    pub service: Arc<IntegrationsService>,
}

pub fn integration_routes(service: IntegrationsService) -> Router {
    let state = IntegrationsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route("/integrations", get(list_integrations))
        .route("/integrations/{provider}", get(get_integration))
        .route("/integrations/{provider}", put(update_integration))
        .route(
            "/integrations/{provider}/connect",
            post(connect_integration),
        )
        .route(
            "/integrations/{provider}/disconnect",
            post(disconnect_integration),
        )
        .with_state(state)
}

/// The provider path segment, parsed against the enum rather than passed
/// through as a string.
///
/// A 404 for an unknown one, because the path names a resource that does not
/// exist. Parsing here rather than in the service means the service only ever
/// sees a provider the registry has an entry for, which is what lets
/// `registry::descriptor` be infallible.
///
/// MAPPS-1098: also 404 for a provider whose integrations surface is hidden
/// (payment providers). The row still exists and billing still writes to it
/// via `set_payment_connection`; the HTTP surface here does not expose it so
/// `Settings > Payment Gateways` is the single surface for the lifecycle.
fn parse_provider(raw: &str) -> AppResult<IntegrationProvider> {
    let provider = IntegrationProvider::from_str(raw).ok_or_else(|| {
        AppError::NotFound(format!(
            "{raw} is not an integration provider. The providers are: {}",
            IntegrationProvider::ALL
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    // MAPPS-1098: a payment provider's lifecycle belongs to Settings > Payment
    // Gateways, so the four per-provider routes refuse it. MAPPS-1122 kept this
    // and stopped the LIST sharing the predicate: the panel lists every
    // provider, and only changing one is confined to its own surface.
    if !registry::descriptor(provider).is_writable_on_integrations_page() {
        return Err(AppError::NotFound(format!(
            "{} is configured under Settings > Payment Gateways",
            provider.as_str()
        )));
    }
    Ok(provider)
}

async fn list_integrations(
    State(state): State<IntegrationsRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<IntegrationResponse>>> {
    Ok(Json(state.service.list(user.tenant()).await?))
}

async fn get_integration(
    State(state): State<IntegrationsRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    Path(provider): Path<String>,
) -> AppResult<Json<IntegrationResponse>> {
    let provider = parse_provider(&provider)?;
    Ok(Json(state.service.get(user.tenant(), provider).await?))
}

async fn update_integration(
    State(state): State<IntegrationsRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Path(provider): Path<String>,
    Json(request): Json<UpdateIntegrationRequest>,
) -> AppResult<Json<IntegrationResponse>> {
    let provider = parse_provider(&provider)?;
    request.validate()?;
    Ok(Json(
        state
            .service
            .update(user.tenant(), provider, request, &ctx)
            .await?,
    ))
}

async fn connect_integration(
    State(state): State<IntegrationsRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Path(provider): Path<String>,
    Json(request): Json<ConnectIntegrationRequest>,
) -> AppResult<Json<IntegrationResponse>> {
    let provider = parse_provider(&provider)?;
    request.validate()?;
    Ok(Json(
        state
            .service
            .connect(user.tenant(), provider, request, &ctx)
            .await?,
    ))
}

async fn disconnect_integration(
    State(state): State<IntegrationsRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Path(provider): Path<String>,
) -> AppResult<Json<IntegrationResponse>> {
    let provider = parse_provider(&provider)?;
    Ok(Json(
        state
            .service
            .disconnect(user.tenant(), provider, &ctx)
            .await?,
    ))
}
