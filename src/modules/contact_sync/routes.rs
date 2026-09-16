//! PMS-1212 (PSA-70 phase 2): the connect, status and disconnect routes.
//!
//! Two planes, deliberately:
//!
//! * `/api/v1/integrations/contact-sync/*` is staff, admin-gated. Connecting a
//!   tenant's directory to its CRM is an administrator's act, the same gate the
//!   RMM connection routes carry.
//! * `/api/v1/public/contact-sync/google/callback` is the browser redirect
//!   Google performs, which carries no session by construction. Its credential
//!   is the single-use state parameter (migration 221); it is listed in the
//!   public subtree's inventory in CLAUDE.md for that reason.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use super::service::{ConnectionStatus, ContactSyncService};
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct ContactSyncRouterState {
    pub service: Arc<ContactSyncService>,
}

/// Staff routes, mounted under `/api/v1`.
pub fn contact_sync_routes(service: Arc<ContactSyncService>) -> Router {
    let state = ContactSyncRouterState { service };
    Router::new()
        .route("/integrations/contact-sync", get(get_connection))
        .route(
            "/integrations/contact-sync/google/authorize",
            post(begin_connect),
        )
        .route(
            "/integrations/contact-sync/google/disconnect",
            post(disconnect),
        )
        .with_state(state)
}

/// The public callback, mounted under `/api/v1/public`.
pub fn contact_sync_public_routes(service: Arc<ContactSyncService>) -> Router {
    let state = ContactSyncRouterState { service };
    Router::new()
        .route("/contact-sync/google/callback", get(callback))
        .with_state(state)
}

/// What the Settings card reads. `None` means never connected, which the card
/// renders as an offer rather than as an error.
async fn get_connection(
    State(state): State<ContactSyncRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Option<ConnectionStatus>>> {
    Ok(Json(state.service.connection(user.tenant()).await?))
}

#[derive(Debug, serde::Serialize)]
struct AuthorizeResponse {
    /// Where to send the admin's browser. The SPA navigates to it rather than
    /// the server redirecting, so the page can warn first: this is the moment
    /// a customer's personal data starts moving into a shared system (PSA-70 K).
    authorize_url: String,
}

/// POST, not GET: it writes a state row. A GET that mutates is a GET a browser
/// can be made to perform.
async fn begin_connect(
    State(state): State<ContactSyncRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<AuthorizeResponse>> {
    let authorize_url = state.service.begin_connect(user.tenant(), user.id).await?;
    Ok(Json(AuthorizeResponse { authorize_url }))
}

async fn disconnect(
    State(state): State<ContactSyncRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
) -> AppResult<axum::http::StatusCode> {
    state.service.disconnect(user.tenant(), &ctx).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// What Google appends to the redirect. `error` arrives when the admin pressed
/// Cancel on the consent screen, which is not a failure worth a stack trace.
#[derive(Debug, Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// The browser lands here, and leaves again immediately.
///
/// Always a redirect back to the SPA, never a JSON error: a person is looking
/// at this, and the outcome belongs on the Settings page they started from.
/// The reason is a flag in the query, never the provider's text, because this
/// URL ends up in a browser history.
async fn callback(
    State(state): State<ContactSyncRouterState>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    if let Some(reason) = query.error.as_deref() {
        // `access_denied` is the admin pressing Cancel; anything else is
        // Google refusing the request itself. Neither is exceptional.
        tracing::info!(reason, "the Google consent screen returned without a code");
        return Redirect::to(&state.service.failure_redirect());
    }
    let (Some(code), Some(state_param)) = (query.code.as_deref(), query.state.as_deref()) else {
        return Redirect::to(&state.service.failure_redirect());
    };
    match state.service.complete_connect(state_param, code).await {
        Ok(destination) => Redirect::to(&destination),
        Err(e) => {
            // Logged with its shape, on the server, where an operator can see
            // it. The browser is told only that it failed.
            tracing::warn!("Google Contacts connect failed: {e}");
            Redirect::to(&state.service.failure_redirect())
        }
    }
}
