//! HTTP surface for the integrations page (PMS-1310).
//!
//! parity record 2026-09-25: no route in this file has an SPA caller yet. The
//! admin integrations page is the mokosh-apps half of PMS-1310 and is its own
//! issue; this module is what it will read. The note covers every route here
//! and comes off with the first one the client calls.
//!
//! Mounted at `/api/v1/integrations` by `create_api_router`, so the paths here
//! are relative to that prefix. `/capabilities` is registered BEFORE
//! `/{provider}` so the literal segment wins the path match, the
//! `portal_role_routes` ordering: a bare `/{provider}` would swallow it and 400
//! on the parse.
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
        .route("/integrations/capabilities", get(list_capabilities))
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
fn parse_provider(raw: &str) -> AppResult<IntegrationProvider> {
    IntegrationProvider::from_str(raw).ok_or_else(|| {
        AppError::NotFound(format!(
            "{raw} is not an integration provider. The providers are: {}",
            IntegrationProvider::ALL
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })
}

async fn list_integrations(
    State(state): State<IntegrationsRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<IntegrationResponse>>> {
    Ok(Json(state.service.list(user.tenant()).await?))
}

/// The whole capability vocabulary, with labels.
///
/// Served rather than compiled into the client for the reason the
/// `mokosh_types::integrations` module doc gives: what a provider supports is a
/// property of this build, and a client holding its own copy would offer a
/// delegation the server would refuse. A provider's supported subset rides on
/// each row in the list; this endpoint is the full catalog behind it.
async fn list_capabilities(
    _admin: RequireAdmin,
    RequireAuth(_user): RequireAuth,
) -> AppResult<Json<Vec<CapabilityDescriptorResponse>>> {
    Ok(Json(
        Capability::ALL
            .iter()
            .copied()
            .map(CapabilityDescriptorResponse::from)
            .collect(),
    ))
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
