//! PMS-731: HTTP routes for form definitions and submissions.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use super::models::{
    CreateFormDefinitionRequest, FormDefinitionResponse, FormSubmissionResponse,
    IssueRequestLinkRequest, RequestLinkResponse, SubmitFormRequest, UpdateFormDefinitionRequest,
};
use super::service::FormsService;
use crate::modules::auth::{RequireAdminUser, RequireAuth, TenantScoped};
use crate::utils::error::AppResult;

#[derive(Clone)]
struct FormsRouterState {
    service: Arc<FormsService>,
    /// SPA origin the emailed request link is built from (PMS-730), the same
    /// base the portal setup link uses.
    app_url: String,
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    /// Narrows the list to forms a client could actually be sent. Defaults to
    /// false so the admin management screen sees retired definitions too.
    #[serde(default)]
    active_only: bool,
}

pub fn forms_routes(service: FormsService, app_url: String) -> Router {
    let state = FormsRouterState {
        service: Arc::new(service),
        app_url,
    };
    Router::new()
        .route("/forms", get(list).post(create))
        .route("/forms/{id}", get(get_one).patch(update).delete(delete_one))
        .route(
            "/forms/{id}/submissions",
            get(list_submissions).post(submit),
        )
        // PMS-730: issue a client a magic link to a form, and see which links
        // have gone out for a company.
        .route(
            "/form-request-links",
            get(list_request_links).post(issue_request_link),
        )
        .with_state(state)
}

// Authoring a definition is admin-gated, matching ticket templates and
// workflow rules: it is tenant-wide configuration, not per-agent data.
// Reading a form and submitting to it are open to any authenticated agent,
// because an agent filling a request on a client's behalf is a normal path.
// The unauthenticated client-facing route arrives with the PMS-730 magic
// link, which resolves its own tenant from the token; it is deliberately not
// mounted here, where the tenant comes from the caller's own session.

async fn list(
    State(s): State<FormsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<FormDefinitionResponse>>> {
    Ok(Json(s.service.list(u.tenant(), q.active_only).await?))
}

async fn get_one(
    State(s): State<FormsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<FormDefinitionResponse>> {
    Ok(Json(s.service.get(u.tenant(), id).await?))
}

async fn create(
    State(s): State<FormsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Json(body): Json<CreateFormDefinitionRequest>,
) -> AppResult<Json<FormDefinitionResponse>> {
    body.validate()?;
    Ok(Json(s.service.create(u.tenant(), u.id, body).await?))
}

async fn update(
    State(s): State<FormsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateFormDefinitionRequest>,
) -> AppResult<Json<FormDefinitionResponse>> {
    body.validate()?;
    Ok(Json(s.service.update(u.tenant(), id, body).await?))
}

async fn delete_one(
    State(s): State<FormsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    s.service.delete(u.tenant(), id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn submit(
    State(s): State<FormsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(body): Json<SubmitFormRequest>,
) -> AppResult<Json<FormSubmissionResponse>> {
    // `submitted_by_contact_id` stays None on this path: the submitter is an
    // authenticated agent, not a client contact. PMS-730's magic-link route
    // is what populates it.
    Ok(Json(
        s.service
            .submit(u.tenant(), id, &body.payload, None)
            .await?,
    ))
}

async fn list_submissions(
    State(s): State<FormsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<FormSubmissionResponse>>> {
    Ok(Json(s.service.list_submissions(u.tenant(), id).await?))
}

// PMS-730: sending a client a request link is ordinary agent work (the person
// handling the account emails the form), so it is RequireAuth rather than
// admin-gated. Authoring the definition it points at stays admin-only above.

async fn issue_request_link(
    State(s): State<FormsRouterState>,
    RequireAuth(u): RequireAuth,
    Json(body): Json<IssueRequestLinkRequest>,
) -> AppResult<Json<RequestLinkResponse>> {
    body.validate()?;
    Ok(Json(
        s.service
            .issue_request_link(u.tenant(), u.id, &body, &s.app_url)
            .await?,
    ))
}

#[derive(Debug, Deserialize)]
struct RequestLinkQuery {
    /// Narrow to one client. Absent lists every link the tenant has issued,
    /// newest first.
    company_id: Option<Uuid>,
}

async fn list_request_links(
    State(s): State<FormsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(q): Query<RequestLinkQuery>,
) -> AppResult<Json<Vec<RequestLinkResponse>>> {
    Ok(Json(
        s.service
            .list_request_links(u.tenant(), q.company_id)
            .await?,
    ))
}
