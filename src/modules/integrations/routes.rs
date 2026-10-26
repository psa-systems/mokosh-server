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
/// MAPPS-1098: also 404 for a provider whose lifecycle belongs to another
/// settings surface. The row still exists and the owning subsystem still
/// writes to it; the HTTP surface here does not expose it, so that one
/// surface is the single place the lifecycle happens.
///
/// MAPPS-1153: that is now every provider in the registry. The payment
/// providers are the payments surface's, the three contact sources are
/// contact sync's, and the two invoice issuers are their own pages' - so
/// these four routes currently serve nobody. They are kept rather than
/// deleted because the registry is the one place that decides, and a
/// provider whose credential does arrive in a connect request would be
/// served by them again without a route being rebuilt.
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
    // MAPPS-1098: a provider whose lifecycle belongs elsewhere is refused
    // here. MAPPS-1122 kept this and stopped the LIST sharing the predicate:
    // the panel lists every provider, and only CHANGING one is confined to
    // its own surface.
    //
    // MAPPS-1153: the message names that surface from the registry rather
    // than saying "Settings > Payment Gateways" the way it used to. That was
    // true while the payment providers were the only refused ones and became
    // a lie the moment they were not: it would have sent a Xero admin to the
    // payments page.
    let descriptor = registry::descriptor(provider);
    if !descriptor.is_writable_on_integrations_page() {
        return Err(AppError::NotFound(match descriptor.setup_surface() {
            Some(surface) => format!(
                "{} is configured under {}",
                provider.as_str(),
                surface.label
            ),
            None => format!("{} is not configured here", provider.as_str()),
        }));
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
