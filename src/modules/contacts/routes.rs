//! Contact API routes

use axum::{
    extract::{Path, Query, Request, State},
    middleware,
    middleware::Next,
    response::Response,
    routing::{delete, get, post, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use axum::response::IntoResponse;

use crate::modules::contact_portal::middleware::ContactAuthState;
use crate::utils::error::AppError;

use super::{
    CompanyFilter, CompanyIndustryResponse, CompanyResponse, ContactFieldValuesQuery,
    ContactFilter, ContactResponse, ContactService, CreateCompanyRequest, CreateContactRequest,
    CreateSiteRequest, GrantPortalAccessRequest, PortalGrantOutcome, PortalRoleSummary,
    SiteResponse, UpdateCompanyRequest, UpdateContactRequest, UpdateSiteRequest,
    UpsertCompanyIndustryRequest,
};
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::modules::portal_roles::{
    CreatePortalRoleRequest, PortalRole, PortalRoleService, UpdatePortalRoleRequest,
};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct ContactRouterState {
    pub contact_service: Arc<ContactService>,
    /// PMS-929 (prompt 012): the nested Company-scoped portal-role
    /// endpoints under `/api/v1/contacts/companies/{company_id}/portal-roles`
    /// delegate straight into `PortalRoleService`, so the state holds a
    /// handle to it. Shared with the top-level `/api/v1/portal-roles`
    /// mount (same underlying service, one pool).
    pub portal_role_service: Arc<PortalRoleService>,
}

/// Create the contact management router
///
/// PMS-929 (prompt 012): also accepts a `PortalRoleService` so the
/// nested Company-scoped role endpoints under
/// `/api/v1/contacts/companies/{company_id}/portal-roles` delegate into
/// the same service that backs the top-level `/api/v1/portal-roles`
/// mount. Passing it in (rather than building a second one here) keeps
/// the pool + audit ctx path identical across both surfaces.
pub fn contact_routes(
    contact_service: ContactService,
    portal_role_service: PortalRoleService,
) -> Router {
    let state = ContactRouterState {
        contact_service: Arc::new(contact_service),
        portal_role_service: Arc::new(portal_role_service),
    };

    Router::new()
        // Companies
        .route("/companies", get(list_companies))
        .route("/companies", post(create_company))
        .route("/companies/{company_id}", get(get_company))
        .route("/companies/{company_id}", put(update_company))
        .route("/companies/{company_id}", delete(delete_company))
        .route(
            "/companies/{company_id}/contacts",
            get(get_company_contacts),
        )
        .route("/companies/{company_id}/sites", get(get_company_sites))
        // PMS-929 (prompt 012): Company-scoped portal-role CRUD. The
        // Company detail page hits these for the "Roles this Company
        // owns" section; the picker on ContactPortalCard hits GET for
        // the tenant-wide-plus-scoped union view.
        .route(
            "/companies/{company_id}/portal-roles",
            get(list_company_portal_roles).post(create_company_portal_role),
        )
        .route(
            "/companies/{company_id}/portal-roles/{role_id}",
            get(get_company_portal_role)
                .put(update_company_portal_role)
                .delete(delete_company_portal_role),
        )
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
        // mokosh-contact-login prompt 003: portal-access lifecycle
        // for a contact. Guard = staff-only (super_admin/admin/manager,
        // enforced inside the handler); the contact plane never hits
        // these routes. `contact_routes` is nested at `/contacts` in
        // the top-level router, so these paths resolve as
        // `/api/v1/contacts/*` at the HTTP layer.
        .route("/contacts/portal-roles", get(list_portal_roles))
        .route(
            "/contacts/{contact_id}/grant-portal-access",
            post(grant_portal_access),
        )
        .route(
            "/contacts/{contact_id}/resend-portal-invite",
            post(resend_portal_invite),
        )
        .route(
            "/contacts/{contact_id}/revoke-portal-access",
            post(revoke_portal_access),
        )
        .route(
            "/contacts/{contact_id}/portal-roles",
            get(get_contact_portal_role_ids).put(replace_contact_portal_role_ids),
        )
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
        // mokosh-contact-login prompt 008: Companies + Contacts are the
        // staff-owned CRM surface. A portal contact must never reach any
        // route on this router - not even the read side - so the whole
        // sub-router is layered with an explicit 403 for the contact
        // plane. Staff (or unauthenticated) requests pass through and
        // the per-handler `RequireAuth` / `RequireAdmin` extractors run
        // normally.
        .layer(middleware::from_fn(reject_contact_plane))
}

/// mokosh-contact-login prompt 008: block a contact bearer from reaching
/// the Companies + Contacts staff CRM. The presence of a decoded
/// `ContactAuthState.session` is enough to short-circuit with 403; the
/// staff path leaves that extension defaulted and passes through.
async fn reject_contact_plane(request: Request, next: Next) -> Response {
    if let Some(state) = request.extensions().get::<ContactAuthState>() {
        if state.session.is_some() {
            return AppError::Forbidden("The Companies + Contacts CRM is staff-only.".to_string())
                .into_response();
        }
    }
    next.run(request).await
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

// ============================================================================
// mokosh-contact-login prompt 003: PORTAL-ACCESS LIFECYCLE HANDLERS
// ============================================================================

async fn list_portal_roles(
    State(state): State<ContactRouterState>,
    _manager: crate::modules::auth::RequireManager,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<PortalRoleSummary>>> {
    // PMS-929 (prompt 012): this endpoint stays tenant-wide-only. The
    // Company-detail-page union lives under the nested
    // `/companies/{company_id}/portal-roles` GET below.
    let roles = state
        .contact_service
        .list_portal_roles(user.tenant(), None)
        .await?;
    Ok(Json(roles))
}

async fn get_contact_portal_role_ids(
    State(state): State<ContactRouterState>,
    _manager: crate::modules::auth::RequireManager,
    RequireAuth(user): RequireAuth,
    Path(contact_id): Path<Uuid>,
) -> AppResult<Json<Vec<Uuid>>> {
    let ids = state
        .contact_service
        .list_contact_portal_role_ids(user.tenant(), contact_id)
        .await?;
    Ok(Json(ids))
}

async fn grant_portal_access(
    State(state): State<ContactRouterState>,
    _manager: crate::modules::auth::RequireManager,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(contact_id): Path<Uuid>,
    Json(request): Json<GrantPortalAccessRequest>,
) -> AppResult<Json<PortalGrantOutcome>> {
    let outcome = state
        .contact_service
        .grant_portal_access(user.tenant(), contact_id, &request.role_ids, &ctx)
        .await?;
    Ok(Json(outcome))
}

async fn resend_portal_invite(
    State(state): State<ContactRouterState>,
    _manager: crate::modules::auth::RequireManager,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(contact_id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    state
        .contact_service
        .resend_portal_invite(user.tenant(), contact_id, &ctx)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn replace_contact_portal_role_ids(
    State(state): State<ContactRouterState>,
    _manager: crate::modules::auth::RequireManager,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(contact_id): Path<Uuid>,
    Json(request): Json<GrantPortalAccessRequest>,
) -> AppResult<axum::http::StatusCode> {
    state
        .contact_service
        .replace_portal_role_assignments(user.tenant(), contact_id, &request.role_ids, &ctx)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn revoke_portal_access(
    State(state): State<ContactRouterState>,
    _manager: crate::modules::auth::RequireManager,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(contact_id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    state
        .contact_service
        .revoke_portal_access(user.tenant(), contact_id, &ctx)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ============================================================================
// PMS-929 (prompt 012): NESTED COMPANY-SCOPED PORTAL-ROLE HANDLERS
// ============================================================================
//
// These live under `/api/v1/contacts/companies/{company_id}/portal-roles`.
// All five gated on `RequireAdmin` (matching the top-level portal-role
// CRUD in `modules::portal_roles::routes`); the whole router already
// carries `reject_contact_plane` so a contact bearer never reaches them.
//
// The GET list returns the UNION of tenant-wide roles plus this
// Company's own scoped roles, so the ContactPortalCard picker + the
// Company detail page's roles table can drive off the same call.
// CRUD-on-one uses a scope guard: the path's `company_id` must equal
// `role.company_id` (a tenant-wide role or a role owned by a different
// Company both 404 through this surface even though they are visible
// through the top-level `/portal-roles/{id}` GET).

async fn list_company_portal_roles(
    State(state): State<ContactRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    Path(company_id): Path<Uuid>,
) -> AppResult<Json<Vec<PortalRoleSummary>>> {
    let roles = state
        .portal_role_service
        .list_roles(user.tenant(), Some(company_id))
        .await?;
    Ok(Json(roles))
}

async fn create_company_portal_role(
    State(state): State<ContactRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(company_id): Path<Uuid>,
    Json(request): Json<CreatePortalRoleRequest>,
) -> AppResult<Json<PortalRole>> {
    request.validate()?;
    // Defence-in-depth: the body may or may not carry `company_id`.
    // If it does, it must match the path so a client cannot mint a
    // scoped role for a different Company by lying in the body while
    // the path pretends otherwise.
    if let Some(body_cid) = request.company_id {
        if body_cid != company_id {
            return Err(AppError::BadRequest(
                "company_id in body must equal the path company_id".to_string(),
            ));
        }
    }
    let role = state
        .portal_role_service
        .create_role(
            user.tenant(),
            Some(company_id),
            request.name,
            request.capabilities,
            &ctx,
        )
        .await?;
    Ok(Json(role))
}

/// Ensure the role at `role_id` is scoped to `company_id` under the
/// caller's tenant. A tenant-wide role or a role owned by a different
/// Company returns 404 through this surface (they exist, but this
/// scoped surface is deliberately blind to anything not owned by the
/// path Company). Callers use this before every one-role handler so
/// the same 404 shape applies to GET/PUT/DELETE.
async fn require_role_in_company_scope(
    state: &ContactRouterState,
    tenant: crate::modules::auth::TenantId,
    company_id: Uuid,
    role_id: Uuid,
) -> AppResult<PortalRole> {
    let role = state.portal_role_service.get_role(tenant, role_id).await?;
    if role.company_id != Some(company_id) {
        return Err(AppError::NotFound("Portal role".to_string()));
    }
    Ok(role)
}

async fn get_company_portal_role(
    State(state): State<ContactRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    Path((company_id, role_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<PortalRole>> {
    let role = require_role_in_company_scope(&state, user.tenant(), company_id, role_id).await?;
    Ok(Json(role))
}

async fn update_company_portal_role(
    State(state): State<ContactRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path((company_id, role_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdatePortalRoleRequest>,
) -> AppResult<Json<PortalRole>> {
    request.validate()?;
    let _ = require_role_in_company_scope(&state, user.tenant(), company_id, role_id).await?;
    let role = state
        .portal_role_service
        .update_role(
            user.tenant(),
            role_id,
            request.name,
            request.capabilities,
            &ctx,
        )
        .await?;
    Ok(Json(role))
}

async fn delete_company_portal_role(
    State(state): State<ContactRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path((company_id, role_id)): Path<(Uuid, Uuid)>,
) -> AppResult<axum::http::StatusCode> {
    let _ = require_role_in_company_scope(&state, user.tenant(), company_id, role_id).await?;
    state
        .portal_role_service
        .delete_role(user.tenant(), role_id, &ctx)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
