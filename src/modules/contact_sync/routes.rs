//! PMS-1212 (PSA-70 phase 2): the connect, status and disconnect routes.
//!
//! Two planes, deliberately:
//!
//! * `/api/v1/integrations/contact-sync/*` is staff. Connecting, choosing
//!   labels, starting or cancelling an import and listing the Google labels are
//!   admin-gated, the gate the RMM connection routes carry. Reading status and
//!   run progress, and reading and answering the review queue, carry
//!   `RequireAuth` (PMS-1215).
//! * `/api/v1/contacts/contacts/{contact_id}/sync*` is one contact's
//!   provenance, its locks, unlinking it, and removing its imported data
//!   (PMS-1214). The doubled segment is the contacts module's own `/contacts`
//!   nest, so these sit beside the contact they describe. Reading, releasing a
//!   lock and unlinking carry `RequireAuth`, the gate editing the contact
//!   itself carries, since each is a smaller act than an edit. Removing
//!   imported data deletes a person and is admin-only.
//! * `/api/v1/public/contact-sync/google/callback` is the browser redirect
//!   Google performs, which carries no session by construction. Its credential
//!   is the single-use state parameter (migration 221); it is listed in the
//!   public subtree's inventory in CLAUDE.md for that reason.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use super::runs::RunStatus;
use super::service::{
    ConnectionStatus, ContactProvenance, ContactSyncService, DataRemoval, GroupOption, Resolution,
    Resolved, ReviewItem,
};
use crate::modules::audit::AuditCtx;
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
        .route("/integrations/contact-sync/groups", get(list_groups))
        .route("/integrations/contact-sync/selection", put(set_selection))
        .route(
            "/integrations/contact-sync/runs",
            get(list_runs).post(queue_run),
        )
        .route("/integrations/contact-sync/runs/{run_id}", get(get_run))
        .route(
            "/integrations/contact-sync/runs/{run_id}/cancel",
            post(cancel_run),
        )
        .route("/integrations/contact-sync/review-queue", get(review_queue))
        .route(
            "/integrations/contact-sync/review-queue/resolve",
            post(resolve),
        )
        .route("/contacts/contacts/{contact_id}/sync", get(get_provenance))
        .route(
            "/contacts/contacts/{contact_id}/sync/locks/{field}",
            delete(release_lock),
        )
        .route("/contacts/contacts/{contact_id}/sync/unlink", post(unlink))
        .route(
            "/contacts/contacts/{contact_id}/sync/remove-imported-data",
            post(remove_imported_data),
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
    ctx: AuditCtx,
) -> AppResult<StatusCode> {
    state.service.disconnect(user.tenant(), &ctx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The labels with Google's counts, for the picker and its preview. Admin:
/// it spends the tenant's grant on a read of their Google account.
async fn list_groups(
    State(state): State<ContactSyncRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<GroupOption>>> {
    Ok(Json(state.service.groups(user.tenant()).await?))
}

#[derive(Debug, Deserialize)]
struct SelectionRequest {
    group_ids: Vec<String>,
}

async fn set_selection(
    State(state): State<ContactSyncRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Json(request): Json<SelectionRequest>,
) -> AppResult<Json<ConnectionStatus>> {
    Ok(Json(
        state
            .service
            .set_selection(user.tenant(), &request.group_ids, &ctx)
            .await?,
    ))
}

#[derive(Debug, Deserialize)]
struct RunsQuery {
    #[serde(default)]
    limit: Option<i64>,
}

async fn list_runs(
    State(state): State<ContactSyncRouterState>,
    RequireAuth(user): RequireAuth,
    Query(query): Query<RunsQuery>,
) -> AppResult<Json<Vec<RunStatus>>> {
    Ok(Json(
        state
            .service
            .runs(user.tenant(), query.limit.unwrap_or(20))
            .await?,
    ))
}

/// 202: the run is queued, and the worker does the import. The response is
/// the row to poll, never the import's result.
async fn queue_run(
    State(state): State<ContactSyncRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
) -> AppResult<(StatusCode, Json<RunStatus>)> {
    let run = state.service.queue_run(user.tenant(), &ctx).await?;
    Ok((StatusCode::ACCEPTED, Json(run)))
}

async fn get_run(
    State(state): State<ContactSyncRouterState>,
    RequireAuth(user): RequireAuth,
    Path(run_id): Path<Uuid>,
) -> AppResult<Json<RunStatus>> {
    Ok(Json(state.service.run(user.tenant(), run_id).await?))
}

async fn cancel_run(
    State(state): State<ContactSyncRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Path(run_id): Path<Uuid>,
) -> AppResult<Json<RunStatus>> {
    Ok(Json(
        state
            .service
            .cancel_run(user.tenant(), run_id, &ctx)
            .await?,
    ))
}

/// Reading and answering the queue carry `RequireAuth`, the gate on reading
/// and editing a contact: each answer is a link, a create or a skip of one.
async fn review_queue(
    State(state): State<ContactSyncRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<ReviewItem>>> {
    Ok(Json(state.service.review_queue(user.tenant()).await?))
}

async fn resolve(
    State(state): State<ContactSyncRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Json(resolution): Json<Resolution>,
) -> AppResult<Json<Resolved>> {
    Ok(Json(
        state
            .service
            .resolve(user.tenant(), &resolution, &ctx)
            .await?,
    ))
}

async fn get_provenance(
    State(state): State<ContactSyncRouterState>,
    RequireAuth(user): RequireAuth,
    Path(contact_id): Path<Uuid>,
) -> AppResult<Json<ContactProvenance>> {
    Ok(Json(
        state.service.provenance(user.tenant(), contact_id).await?,
    ))
}

async fn release_lock(
    State(state): State<ContactSyncRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Path((contact_id, field)): Path<(Uuid, String)>,
) -> AppResult<StatusCode> {
    state
        .service
        .release_lock(user.tenant(), contact_id, &field, &ctx)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unlink(
    State(state): State<ContactSyncRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Path(contact_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state
        .service
        .unlink(user.tenant(), contact_id, &ctx)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct RemoveImportedDataRequest {
    /// Who asked, or why. Required: this deletes a person's data, and the
    /// audit row is the only account of it that remains.
    #[serde(default)]
    reason: String,
}

/// POST with a body rather than DELETE: it takes a reason, and it is not a
/// delete of the resource at this path.
async fn remove_imported_data(
    State(state): State<ContactSyncRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: AuditCtx,
    Path(contact_id): Path<Uuid>,
    Json(request): Json<RemoveImportedDataRequest>,
) -> AppResult<Json<DataRemoval>> {
    Ok(Json(
        state
            .service
            .remove_imported_data(user.tenant(), contact_id, &request.reason, &ctx)
            .await?,
    ))
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
