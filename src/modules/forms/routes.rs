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

use super::drafts::{FormDraftResponse, UpsertFormDraftRequest};
use super::models::{
    CreateFormDefinitionRequest, FormDefinitionResponse, FormSubmissionResponse,
    IssueRequestLinkRequest, RequestLinkResponse, UpdateFormDefinitionRequest,
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
        // PMS-759: before `/forms/{id}`, so `drafts` is not parsed as a form id.
        .route("/forms/drafts", get(list_drafts).put(upsert_draft))
        .route("/forms/drafts/{id}", axum::routing::delete(delete_draft))
        // PMS-840: no `delete`. A definition is retired with `is_active`, and a
        // hard delete is refused anyway once `form_submissions` points at it.
        .route("/forms/{id}", get(get_one).patch(update))
        // PMS-840: read only. The agent-side submit went with the delete.
        .route("/forms/{id}/submissions", get(list_submissions))
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
// Reading a form and issuing a client a link are open to any authenticated
// agent, because sending a request out is ordinary account work.
// The unauthenticated client-facing route arrives with the PMS-730 magic
// link, which resolves its own tenant from the token; it is deliberately not
// mounted here, where the tenant comes from the caller's own session.

// PMS-840 parity record. Every route above is either called from
// `mokosh-apps/src/` or accounted for here, so none sits in the ambiguous
// middle. Verified against mokosh-apps `123442d` on 2026-08-22.
//
// Called by the SPA: `GET`/`POST /forms` and `PATCH /forms/{id}`
// (`pages/forms.rs`), `GET /forms?active_only=true` and
// `GET`/`POST /form-request-links` (`pages/request_links.rs`), and the whole
// `/forms/drafts` group (`pages/forms.rs`, PMS-759).
//
// Backend-only, no SPA caller wanted: `GET /forms/{id}`. The SPA lists every
// definition and edits from that list, so a by-id read is redundant there; it
// stays for API clients and is the shape `tests/forms.rs` reads back with.
//
// No SPA caller yet, and that is the gap: `GET /forms/{id}/submissions`. A
// client's answers are otherwise unreadable once rendered into the ticket
// description. The Submissions view is tracked in PMS-869.
//
// Removed here rather than built: `POST /forms/{id}/submissions` and
// `DELETE /forms/{id}`. Neither had a caller anywhere. Agent-fills-on-behalf
// has no surface and no asked-for product need, and the PMS-730 magic link is
// now the only way a submission is created; retirement via `is_active` is the
// operator's delete, and a hard delete was refused anyway once a submission
// pointed at the definition. `retired_routes_stay_unmounted` is the guard.

async fn list(
    State(s): State<FormsRouterState>,
    RequireAuth(u): RequireAuth,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<FormDefinitionResponse>>> {
    Ok(Json(s.service.list(u.tenant(), q.active_only).await?))
}

/// PMS-840: backend-only. Nothing in `mokosh-apps/src/` fetches a definition
/// by id (the editor works from the `GET /forms` list), so this serves API
/// clients and the integration suite, not a screen.
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
    let created = s.service.create(u.tenant(), u.id, body).await?;
    // PMS-759: the work is on the server now, so the "new form" draft has
    // nothing left to protect. Cleared here rather than left to the SPA: a
    // draft exists to survive the browser going away, so it cannot depend on
    // the browser to tidy up.
    s.service
        .clear_form_draft_after_save(u.tenant(), u.id, None)
        .await;
    Ok(Json(created))
}

async fn update(
    State(s): State<FormsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateFormDefinitionRequest>,
) -> AppResult<Json<FormDefinitionResponse>> {
    body.validate()?;
    let updated = s.service.update(u.tenant(), id, body).await?;
    s.service
        .clear_form_draft_after_save(u.tenant(), u.id, Some(id))
        .await;
    Ok(Json(updated))
}

/// PMS-759: the caller's own drafts. Admin-gated to match `create` / `update`:
/// a draft is a half-written definition, and the people who can author one are
/// the people who can hold one.
async fn list_drafts(
    State(s): State<FormsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
) -> AppResult<Json<Vec<FormDraftResponse>>> {
    Ok(Json(s.service.list_form_drafts(u.tenant(), u.id).await?))
}

async fn upsert_draft(
    State(s): State<FormsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Json(body): Json<UpsertFormDraftRequest>,
) -> AppResult<Json<FormDraftResponse>> {
    Ok(Json(
        s.service.upsert_form_draft(u.tenant(), u.id, &body).await?,
    ))
}

async fn delete_draft(
    State(s): State<FormsRouterState>,
    RequireAdminUser(u): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    s.service.delete_form_draft(u.tenant(), u.id, id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// PMS-869: the reader for a form's answers. No SPA caller yet; see the
/// parity record above.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use axum::body::Body;
    use axum::http::StatusCode;
    use sqlx::postgres::PgPool;
    use tower::ServiceExt;

    /// PMS-840: `POST /forms/{id}/submissions` and `DELETE /forms/{id}` were
    /// retired as unconsumed. This is the mechanical guard: re-mounting either
    /// method turns these 405s into a real response and fails here.
    ///
    /// Rejecting a method never touches the database, so the lazy pool is
    /// never connected. The sibling methods on the same paths are asserted NOT
    /// to be 405 so a typo that unmounts the whole path cannot pass.
    #[tokio::test]
    async fn retired_routes_stay_unmounted() {
        let pool = PgPool::connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool builds without connecting");
        let router = forms_routes(
            FormsService::new(Database::from_pool(pool)),
            "http://spa.example".to_string(),
        );
        let id = Uuid::new_v4();

        let request = |method: &str, uri: String| {
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .expect("request builds")
        };

        for (method, uri) in [
            ("POST", format!("/forms/{id}/submissions")),
            ("DELETE", format!("/forms/{id}")),
        ] {
            let response = router
                .clone()
                .oneshot(request(method, uri.clone()))
                .await
                .expect("router responds");
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {uri} must stay unmounted (PMS-840)"
            );
        }

        for (method, uri) in [
            ("GET", format!("/forms/{id}/submissions")),
            ("GET", format!("/forms/{id}")),
        ] {
            let response = router
                .clone()
                .oneshot(request(method, uri.clone()))
                .await
                .expect("router responds");
            assert_ne!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {uri} is the surviving method and must still route"
            );
        }
    }
}
