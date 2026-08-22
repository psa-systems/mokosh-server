//! Contact API routes

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    CompanyFilter, CompanyIndustryResponse, CompanyResponse, ContactFieldValuesQuery,
    ContactFilter, ContactResponse, ContactService, CreateCompanyRequest, CreateContactRequest,
    CreateSiteRequest, SiteResponse, UpdateCompanyRequest, UpdateContactRequest, UpdateSiteRequest,
    UpsertCompanyIndustryRequest, WebsiteProbeLimiter, WebsiteProbeService,
};
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::{rate_limited_response, AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct ContactRouterState {
    pub contact_service: Arc<ContactService>,
    /// PMS-805. `None` only when the probe's HTTP client could not be built,
    /// which is logged at `error` here and surfaces as a 500 on the endpoint
    /// rather than as a site that silently reports itself unreachable.
    pub website_probe: Option<Arc<WebsiteProbeService>>,
    pub website_probe_limiter: Arc<WebsiteProbeLimiter>,
}

/// Create the contact management router
pub fn contact_routes(contact_service: ContactService) -> Router {
    let website_probe = match WebsiteProbeService::live() {
        Ok(service) => Some(service),
        Err(e) => {
            tracing::error!(error = %e, "website probe disabled: HTTP client could not be built");
            None
        }
    };
    let state = ContactRouterState {
        contact_service: Arc::new(contact_service),
        website_probe,
        website_probe_limiter: WebsiteProbeLimiter::new(),
    };

    Router::new()
        // Companies
        .route("/companies", get(list_companies))
        .route("/companies", post(create_company))
        // PMS-805: static segment, so it resolves ahead of the
        // `{company_id}` routes below (same shape as
        // `/contacts/field-values`).
        .route("/companies/website-probe", get(probe_company_website))
        .route("/companies/{company_id}", get(get_company))
        .route("/companies/{company_id}", put(update_company))
        .route("/companies/{company_id}", delete(delete_company))
        .route(
            "/companies/{company_id}/contacts",
            get(get_company_contacts),
        )
        .route("/companies/{company_id}/sites", get(get_company_sites))
        // Contacts
        .route("/contacts", get(list_contacts))
        .route("/contacts", post(create_contact))
        // PMS-583: distinct title/department values for the free-text
        // autocomplete. Static segment, so it resolves ahead of the
        // `{contact_id}` route below.
        .route("/contacts/field-values", get(list_contact_field_values))
        .route("/contacts/{contact_id}", get(get_contact))
        .route("/contacts/{contact_id}", put(update_contact))
        .route("/contacts/{contact_id}", delete(delete_contact))
        // Company industries lookup (PMS-601). Reads are open to any authed
        // user (the company form's combobox needs them); writes are admin-only.
        .route(
            "/company-industries",
            get(list_company_industries).post(create_company_industry),
        )
        .route(
            "/company-industries/{id}",
            put(update_company_industry).delete(delete_company_industry),
        )
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
        .list_companies(user.tenant(), &filter, &pagination)
        .await?;

    let responses: Vec<CompanyResponse> =
        companies.into_iter().map(CompanyResponse::from).collect();
    let enriched = state
        .contact_service
        .enrich_companies(user.tenant(), responses)
        .await?;
    let response = PaginatedResponse::from_params(enriched, &pagination, total);

    Ok(Json(response))
}

async fn create_company(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateCompanyRequest>,
) -> AppResult<Json<CompanyResponse>> {
    request.validate()?;

    let company = state
        .contact_service
        .create_company(user.tenant(), &request, &ctx)
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
        .get_company(user.tenant(), company_id)
        .await?;

    let enriched = state
        .contact_service
        .enrich_companies(user.tenant(), vec![CompanyResponse::from(company)])
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| crate::utils::error::AppError::NotFound("Company".to_string()))?;
    Ok(Json(enriched))
}

async fn update_company(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(company_id): Path<Uuid>,
    Json(request): Json<UpdateCompanyRequest>,
) -> AppResult<Json<CompanyResponse>> {
    request.validate()?;

    let company = state
        .contact_service
        .update_company(user.tenant(), company_id, &request, &ctx)
        .await?;

    Ok(Json(company.into()))
}

async fn delete_company(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(company_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .contact_service
        .delete_company(user.tenant(), company_id, &ctx)
        .await
}

async fn get_company_contacts(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ContactResponse>>> {
    let (contacts, total) = state
        .contact_service
        .get_company_contacts(user.tenant(), company_id, &pagination)
        .await?;

    let items: Vec<ContactResponse> = contacts.into_iter().map(ContactResponse::from).collect();
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_company_sites(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<SiteResponse>>> {
    let (sites, total) = state
        .contact_service
        .get_company_sites(user.tenant(), company_id, &pagination)
        .await?;

    let items: Vec<SiteResponse> = sites.into_iter().map(SiteResponse::from).collect();
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

/// PMS-805: `GET /companies/website-probe?url=<value>`.
#[derive(Debug, Deserialize)]
pub struct WebsiteProbeQuery {
    pub url: String,
}

/// Resolve a website and report what answered.
///
/// Reads and writes no tenant data; the tenant is used only as the rate-limit
/// key. Both the reachable and the unreachable case are 200s, because
/// determining that a site does not answer is a successful probe. Input that
/// cannot be a website at all is a 400 instead, so the form can tell "you typed
/// something that is not a URL" apart from "your site is down".
async fn probe_company_website(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Query(query): Query<WebsiteProbeQuery>,
) -> Result<Response, AppError> {
    if let Err(retry_after) = state.website_probe_limiter.check(*user.tenant()) {
        tracing::warn!(
            tenant_id = %user.tenant(),
            retry_after,
            "website probe rate limited"
        );
        return Ok(rate_limited_response(
            retry_after,
            "Too many website probes, please try again shortly",
        ));
    }

    let Some(service) = state.website_probe.as_ref() else {
        return Err(AppError::Configuration(
            "The website probe is unavailable.".to_string(),
        ));
    };

    Ok(Json(service.probe_input(&query.url).await?).into_response())
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
        .list_contacts(user.tenant(), &filter, &pagination)
        .await?;

    let response = PaginatedResponse::from_params(
        contacts.into_iter().map(ContactResponse::from).collect(),
        &pagination,
        total,
    );

    Ok(Json(response))
}

/// PMS-583: distinct existing values of a free-text contact field (title /
/// department) for this tenant, for the contact form's autocomplete. Returns
/// a plain string list ranked by frequency, capped server-side.
async fn list_contact_field_values(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Query(query): Query<ContactFieldValuesQuery>,
) -> AppResult<Json<Vec<String>>> {
    query.validate()?;
    let values = state
        .contact_service
        .distinct_contact_field_values(user.tenant(), query.field, query.q.as_deref())
        .await?;

    Ok(Json(values))
}

async fn create_contact(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateContactRequest>,
) -> AppResult<Json<ContactResponse>> {
    request.validate()?;

    let contact = state
        .contact_service
        .create_contact(user.tenant(), &request, &ctx)
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
        .get_contact(user.tenant(), contact_id)
        .await?;

    Ok(Json(contact.into()))
}

async fn update_contact(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(contact_id): Path<Uuid>,
    Json(request): Json<UpdateContactRequest>,
) -> AppResult<Json<ContactResponse>> {
    request.validate()?;

    let contact = state
        .contact_service
        .update_contact(user.tenant(), contact_id, &request, &ctx)
        .await?;

    Ok(Json(contact.into()))
}

async fn delete_contact(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(contact_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .contact_service
        .delete_contact(user.tenant(), contact_id, &ctx)
        .await
}

// ============================================================================
// SITE HANDLERS
// ============================================================================

async fn create_site(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateSiteRequest>,
) -> AppResult<Json<SiteResponse>> {
    request.validate()?;

    let site = state
        .contact_service
        .create_site(user.tenant(), &request, &ctx)
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
        .get_site(user.tenant(), site_id)
        .await?;

    Ok(Json(site.into()))
}

async fn update_site(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(site_id): Path<Uuid>,
    Json(request): Json<UpdateSiteRequest>,
) -> AppResult<Json<SiteResponse>> {
    request.validate()?;

    let site = state
        .contact_service
        .update_site(user.tenant(), site_id, &request, &ctx)
        .await?;

    Ok(Json(site.into()))
}

async fn delete_site(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(site_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .contact_service
        .delete_site(user.tenant(), site_id, &ctx)
        .await
}

// ============================================================================
// COMPANY-INDUSTRY LOOKUP HANDLERS (PMS-601)
// ============================================================================

async fn list_company_industries(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<CompanyIndustryResponse>>> {
    let (rows, total) = state
        .contact_service
        .list_company_industries(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        rows,
        &pagination,
        total,
    )))
}

async fn create_company_industry(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    _admin: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertCompanyIndustryRequest>,
) -> AppResult<Json<CompanyIndustryResponse>> {
    request.validate()?;
    let row = state
        .contact_service
        .create_company_industry(user.tenant(), &request, &ctx)
        .await?;
    Ok(Json(row))
}

async fn update_company_industry(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertCompanyIndustryRequest>,
) -> AppResult<Json<CompanyIndustryResponse>> {
    request.validate()?;
    let row = state
        .contact_service
        .update_company_industry(user.tenant(), id, &request)
        .await?;
    Ok(Json(row))
}

async fn delete_company_industry(
    State(state): State<ContactRouterState>,
    RequireAuth(user): RequireAuth,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state
        .contact_service
        .delete_company_industry(user.tenant(), id)
        .await
}
