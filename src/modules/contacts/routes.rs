//! Contact API routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    CompanyDetailResponse, CompanyFilter, CompanyResponse, ContactFilter, ContactResponse,
    ContactService, CreateCompanyRequest, CreateContactRequest, CreateSiteRequest, SiteResponse,
    UpdateCompanyRequest, UpdateContactRequest, UpdateSiteRequest,
};
use crate::modules::auth::RequireAuth;
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct ContactRouterState {
    pub contact_service: Arc<ContactService>,
}

/// Create the contact management router
pub fn contact_routes(contact_service: ContactService) -> Router {
    let state = ContactRouterState {
        contact_service: Arc::new(contact_service),
    };

    Router::new()
        // Companies
        .route("/companies", get(list_companies))
        .route("/companies", post(create_company))
        .route("/companies/{company_id}", get(get_company))
        .route("/companies/{company_id}", put(update_company))
        .route("/companies/{company_id}", delete(delete_company))
        .route("/companies/{company_id}/contacts", get(get_company_contacts))
        .route("/companies/{company_id}/sites", get(get_company_sites))
        // Contacts
        .route("/contacts", get(list_contacts))
        .route("/contacts", post(create_contact))
        .route("/contacts/{contact_id}", get(get_contact))
        .route("/contacts/{contact_id}", put(update_contact))
        .route("/contacts/{contact_id}", delete(delete_contact))
        // Sites
        .route("/sites", post(create_site))
        .route("/sites/{site_id}", get(get_site))
        .route("/sites/{site_id}", put(update_site))
        .route("/sites/{site_id}", delete(delete_site))
        .with_state(state)
}

// ============================================================================
// COMPANY HANDLERS
// ============================================================================

async fn list_companies(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Query(filter): Query<CompanyFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<CompanyResponse>>> {
    // F9: validate filter inputs (length caps on free-text fields).
    filter.validate()?;
    let (companies, total) = state
        .contact_service
        .list_companies(user.tenant_id, &filter, &pagination)
        .await?;

    let response = PaginatedResponse::from_params(
        companies.into_iter().map(CompanyResponse::from).collect(),
        &pagination,
        total,
    );

    Ok(Json(response))
}

async fn create_company(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<CreateCompanyRequest>,
) -> AppResult<Json<CompanyResponse>> {
    request.validate()?;

    let company = state
        .contact_service
        .create_company(user.tenant_id, &request)
        .await?;

    Ok(Json(company.into()))
}

async fn get_company(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
) -> AppResult<Json<CompanyResponse>> {
    let company = state
        .contact_service
        .get_company(user.tenant_id, company_id)
        .await?;

    Ok(Json(company.into()))
}

async fn update_company(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
    Json(request): Json<UpdateCompanyRequest>,
) -> AppResult<Json<CompanyResponse>> {
    request.validate()?;

    let company = state
        .contact_service
        .update_company(user.tenant_id, company_id, &request)
        .await?;

    Ok(Json(company.into()))
}

async fn delete_company(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .contact_service
        .delete_company(user.tenant_id, company_id)
        .await
}

async fn get_company_contacts(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
) -> AppResult<Json<Vec<ContactResponse>>> {
    let contacts = state
        .contact_service
        .get_company_contacts(user.tenant_id, company_id)
        .await?;

    Ok(Json(
        contacts.into_iter().map(ContactResponse::from).collect(),
    ))
}

async fn get_company_sites(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
) -> AppResult<Json<Vec<SiteResponse>>> {
    let sites = state
        .contact_service
        .get_company_sites(user.tenant_id, company_id)
        .await?;

    Ok(Json(sites.into_iter().map(SiteResponse::from).collect()))
}

// ============================================================================
// CONTACT HANDLERS
// ============================================================================

async fn list_contacts(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Query(filter): Query<ContactFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ContactResponse>>> {
    // F9: validate filter inputs.
    filter.validate()?;
    let (contacts, total) = state
        .contact_service
        .list_contacts(user.tenant_id, &filter, &pagination)
        .await?;

    let response = PaginatedResponse::from_params(
        contacts.into_iter().map(ContactResponse::from).collect(),
        &pagination,
        total,
    );

    Ok(Json(response))
}

async fn create_contact(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<CreateContactRequest>,
) -> AppResult<Json<ContactResponse>> {
    request.validate()?;

    let contact = state
        .contact_service
        .create_contact(user.tenant_id, &request)
        .await?;

    Ok(Json(contact.into()))
}

async fn get_contact(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(contact_id): Path<Uuid>,
) -> AppResult<Json<ContactResponse>> {
    let contact = state
        .contact_service
        .get_contact(user.tenant_id, contact_id)
        .await?;

    Ok(Json(contact.into()))
}

async fn update_contact(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(contact_id): Path<Uuid>,
    Json(request): Json<UpdateContactRequest>,
) -> AppResult<Json<ContactResponse>> {
    request.validate()?;

    let contact = state
        .contact_service
        .update_contact(user.tenant_id, contact_id, &request)
        .await?;

    Ok(Json(contact.into()))
}

async fn delete_contact(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(contact_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .contact_service
        .delete_contact(user.tenant_id, contact_id)
        .await
}

// ============================================================================
// SITE HANDLERS
// ============================================================================

async fn create_site(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<CreateSiteRequest>,
) -> AppResult<Json<SiteResponse>> {
    request.validate()?;

    let site = state
        .contact_service
        .create_site(user.tenant_id, &request)
        .await?;

    Ok(Json(site.into()))
}

async fn get_site(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(site_id): Path<Uuid>,
) -> AppResult<Json<SiteResponse>> {
    let site = state
        .contact_service
        .get_site(user.tenant_id, site_id)
        .await?;

    Ok(Json(site.into()))
}

async fn update_site(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(site_id): Path<Uuid>,
    Json(request): Json<UpdateSiteRequest>,
) -> AppResult<Json<SiteResponse>> {
    request.validate()?;

    let site = state
        .contact_service
        .update_site(user.tenant_id, site_id, &request)
        .await?;

    Ok(Json(site.into()))
}

async fn delete_site(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(site_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .contact_service
        .delete_site(user.tenant_id, site_id)
        .await
}
