//! PMS-729 phase 2 §7 slice B / I8: authenticated portal form surface.
//!
//! Mounted inside the portal API tree at `/portal/forms*`. Every route
//! sits behind `RequirePortalAuth`; the middleware is layered inside
//! the builder for the same reason `portal_attachment_routes` layers
//! its own copy (a merged sub-router does not inherit the parent's
//! layers).

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;

use super::models::{
    PortalFormListItem, PublicFormResponse, PublicSubmissionReceipt, SubmitFormRequest,
};
use super::service::FormsService;
use crate::modules::portal::middleware::{
    portal_auth_middleware, PortalAuthMiddleware, RequirePortalAuth,
};
use crate::modules::portal::service::PortalAuthService;
use crate::utils::error::AppResult;

#[derive(Clone)]
struct PortalFormsState {
    forms: Arc<FormsService>,
}

pub fn portal_form_routes(forms: FormsService, portal_auth_service: PortalAuthService) -> Router {
    let state = PortalFormsState {
        forms: Arc::new(forms),
    };
    let mw = PortalAuthMiddleware::new(portal_auth_service);
    // The whole portal API tree is nested under `/api/v1/portal`, so
    // these routes register with the leading `/portal` segment stripped.
    Router::new()
        .route("/forms", get(list_portal_forms))
        .route("/forms/{form_id}", get(get_portal_form))
        .route("/forms/{form_id}/submit", post(submit_portal_form))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            mw,
            portal_auth_middleware,
        ))
}

async fn list_portal_forms(
    State(s): State<PortalFormsState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<Vec<PortalFormListItem>>> {
    let items = s.forms.list_portal_forms(contact.tenant()).await?;
    Ok(Json(items))
}

async fn get_portal_form(
    State(s): State<PortalFormsState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(form_id): Path<Uuid>,
) -> AppResult<Json<PublicFormResponse>> {
    let form = s.forms.get_portal_form(contact.tenant(), form_id).await?;
    Ok(Json(form))
}

async fn submit_portal_form(
    State(s): State<PortalFormsState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(form_id): Path<Uuid>,
    Json(body): Json<SubmitFormRequest>,
) -> AppResult<(StatusCode, Json<PublicSubmissionReceipt>)> {
    let receipt = s
        .forms
        .submit_portal_form(
            contact.tenant(),
            form_id,
            contact.company_id,
            contact.id,
            &body.payload,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(receipt)))
}
