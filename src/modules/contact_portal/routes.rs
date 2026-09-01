//! mokosh-contact-login prompt 004: `/api/v1/contact/*` route family.
//!
//! Public routes (login, refresh, logout, set-password, forgot-password,
//! reset-password, host hint) sit outside the auth check; the middleware
//! still runs (it decodes the token when present) but downstream
//! extractors don't. `/auth/me` is behind `RequireContactAuth`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use validator::Validate;

use super::middleware::{portal_contact_middleware, ContactAuthMiddleware, RequireContactAuth};
use super::models::*;
use super::service::ContactAuthService;
use crate::modules::auth::TenantId;
use crate::modules::contact_portal::capabilities as caps;
use crate::utils::error::{AppError, AppResult};

const REFRESH_COOKIE_NAME: &str = "mokosh:contact_token";
const REFRESH_COOKIE_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60; // 30 days

#[derive(Clone)]
pub struct ContactRouterState {
    pub service: Arc<ContactAuthService>,
}

/// Build the `/api/v1/contact/*` sub-router. Layered with
/// `portal_contact_middleware` so every request through this tree
/// decodes the Bearer / cookie into a `ContactAuthState` extension
/// (default when absent); downstream extractors then 401 as needed.
pub fn contact_routes(service: ContactAuthService) -> Router {
    let service_arc = Arc::new(service);
    let mw = ContactAuthMiddleware {
        service: service_arc.clone(),
    };
    let state = ContactRouterState {
        service: service_arc,
    };
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/set-password", post(set_password))
        .route("/auth/reset-password", post(reset_password))
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/login-link", post(request_login_link))
        .route("/auth/login-link/redeem", post(redeem_login_link))
        // MAPPS-637: `/auth/login-link/select` retired. The
        // multi-candidate picker + its "one selection token → any of
        // N contacts" primitive was the "aggregate by email" hazard
        // MAPPS-636 removed the picker for. A caller who hits this
        // URL now 404s.
        .route("/auth/me", get(me).put(update_me))
        // MAPPS-618 (mokosh-branding prompt 002): contact-plane brand
        // editor. Gated on `settings:manage_company_branding`; server
        // derives the target Company from the caller's session, so a
        // holder can only ever paint their own Company's brand.
        //
        // GET returns the raw tenant + Company branding blocks plus
        // the resolved effective set so the SPA renders the
        // "Inherits from MSP default" hints on each field. PATCH
        // JSONB-merges the request into the row (subset the caller
        // owns, explicit null clears; same PMS-758 pattern the tenant
        // side uses).
        .route(
            "/companies/self/branding",
            get(get_own_company_branding).patch(update_own_company_branding),
        )
        // PMS-935: contact-only dashboard aggregate. Staff have their
        // own workspace dashboards; this endpoint is deliberately
        // scoped to `RequireContactAuth`.
        .route("/dashboard/summary", get(dashboard_summary))
        // mokosh-contact-login prompt 011 (PMS-928): one host route
        // that dispatches on the path segment's shape. All-digits
        // parses as a numeric Portal ID; anything else is treated as
        // a legacy Crockford slug. Same URL pattern the spec calls
        // for, no axum route-conflict.
        .route("/portal/{handle}/host", get(portal_host))
        // mokosh-contact-login prompt 011 (PMS-928): client-side
        // compat redirect. The SPA GETs this on mount for the legacy
        // `/portal/{slug}/login` URL, swaps to `/portal/{portal_id}/login`
        // on success, or falls back to the slug-based form on 404.
        .route(
            "/portal/{slug}/resolve-to-portal-id",
            get(resolve_slug_to_portal_id),
        )
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            mw,
            portal_contact_middleware,
        ))
}

// ============================================================================
// HANDLERS
// ============================================================================

async fn login(
    State(state): State<ContactRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ContactLoginRequest>,
) -> Result<Response, AppError> {
    request.validate()?;
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // mokosh-contact-login prompt 011 (PMS-928): body must carry at
    // least one of portal_id / slug. Missing both folds to the same
    // generic 401 the service returns on any unresolved handle so
    // the endpoint stays enumeration-resistant (no distinguishable
    // "you forgot to send a Portal ID" response).
    if request.portal_id.is_none()
        && request
            .slug
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_none()
    {
        return Err(AppError::Unauthorized);
    }
    let resp = state
        .service
        .login(
            request.portal_id,
            request.slug.as_deref(),
            &request.email,
            &request.password,
            request.mfa_code.as_deref(),
            ua.as_deref(),
            Some(addr.ip()),
        )
        .await?;
    Ok(with_refresh_cookie(
        &resp,
        Json(resp.clone()).into_response(),
    ))
}

async fn refresh(
    State(state): State<ContactRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ContactRefreshRequest>,
) -> Result<Response, AppError> {
    request.validate()?;
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let resp = state
        .service
        .refresh(&request.refresh_token, ua.as_deref(), Some(addr.ip()))
        .await?;
    Ok(with_refresh_cookie(
        &resp,
        Json(resp.clone()).into_response(),
    ))
}

async fn logout(
    State(state): State<ContactRouterState>,
    Json(request): Json<ContactLogoutRequest>,
) -> Result<Response, AppError> {
    request.validate()?;
    state.service.logout(&request.refresh_token).await?;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    add_cookie(resp.headers_mut(), &clear_refresh_cookie());
    Ok(resp)
}

async fn set_password(
    State(state): State<ContactRouterState>,
    Json(request): Json<ContactSetPasswordRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    state
        .service
        .setup_password(&request.token, &request.password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reset_password(
    State(state): State<ContactRouterState>,
    Json(request): Json<ContactResetPasswordRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    state
        .service
        .reset_password(&request.token, &request.password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn forgot_password(
    State(state): State<ContactRouterState>,
    Json(request): Json<ContactForgotPasswordRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    state
        .service
        .request_password_reset(&request.slug, &request.email)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// mokosh-contact-login prompt 010 (PMS-918): POST /auth/login-link.
/// Always returns 204 whether the (slug, email) matches a portal
/// contact or not. Enumeration-resistant by construction.
async fn request_login_link(
    State(state): State<ContactRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ContactRequestLoginLinkRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    state
        .service
        .request_login_link(
            &request.email,
            request.slug.as_deref(),
            request.portal_id,
            Some(addr.ip()),
            ua.as_deref(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// mokosh-contact-login prompt 010: POST /auth/login-link/redeem.
/// Returns a `LoginLinkRedeemOutcome` JSON envelope. On the
/// single-match auto path, also sets the refresh cookie so the SPA
/// survives a hard-refresh cold-load.
async fn redeem_login_link(
    State(state): State<ContactRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ContactRedeemLoginLinkRequest>,
) -> Result<Response, AppError> {
    request.validate()?;
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let outcome = state
        .service
        .redeem_login_link(&request.token, ua.as_deref(), Some(addr.ip()))
        .await?;
    // Attach the refresh cookie only on the auto-mint path where a
    // real session was minted (mfa_required = false + tokens set).
    let cookie = outcome
        .auto
        .as_ref()
        .filter(|r| !r.mfa_required && !r.refresh_token.is_empty())
        .map(|r| build_refresh_cookie(&r.refresh_token));
    let mut resp = Json(outcome).into_response();
    if let Some(c) = cookie {
        add_cookie(resp.headers_mut(), &c);
    }
    Ok(resp)
}

// MAPPS-637: `select_login_candidate` handler retired alongside the
// route (see the routes builder above). The service method +
// selection-token machinery are gone; a caller who probes the URL
// gets 404 from axum's route matcher.

async fn me(
    State(state): State<ContactRouterState>,
    RequireContactAuth(session): RequireContactAuth,
) -> AppResult<Json<ContactMe>> {
    let me = state.service.me(session.tenant_id, session.id).await?;
    Ok(Json(me))
}

/// PMS-935: contact profile self-edit. Gated on
/// `settings:manage_own` (DB-loaded per request; JWT `caps` is
/// UI-only so a role revoke lands within one tick, not after the
/// 15-min access-token TTL). Email is NOT accepted here - the staff
/// CRM owns portal identity and portals cannot self-serve an email
/// change. Fields left as `None` are unchanged on the underlying
/// contact row.
async fn update_me(
    State(state): State<ContactRouterState>,
    RequireContactAuth(session): RequireContactAuth,
    Json(request): Json<ContactSelfUpdateRequest>,
) -> AppResult<Json<ContactMe>> {
    request.validate()?;
    // Belt-and-braces: reload the effective cap set from
    // `portal_roles` (mirrors what CallerContext::require_capability
    // does on the dual-plane routes) so a role revoke lands within
    // one tick instead of after the JWT TTL. RequireContactAuth
    // does not go through CallerContext, so the check is inlined
    // through the service's DB handle here.
    let capabilities = state
        .service
        .load_capabilities(session.tenant_id, session.id)
        .await?;
    if !capabilities.iter().any(|c| c == caps::SETTINGS_MANAGE_OWN) {
        return Err(AppError::Forbidden(format!(
            "Missing required capability: {}",
            caps::SETTINGS_MANAGE_OWN
        )));
    }
    let tenant = TenantId::from_trusted(session.tenant_id);
    let me = state
        .service
        .update_self(tenant, session.id, &request)
        .await?;
    Ok(Json(me))
}

/// MAPPS-618 (mokosh-branding prompt 002): read the caller's own
/// Company branding for the contact-plane editor. Returns the raw
/// tenant + Company blocks plus the resolved effective set. Gated on
/// `settings:manage_company_branding` (a contact who cannot edit
/// brand also does not need the raw tenant side; the merged
/// `effective_branding` is already on `ContactMe` for painting).
async fn get_own_company_branding(
    State(state): State<ContactRouterState>,
    RequireContactAuth(session): RequireContactAuth,
) -> AppResult<Json<ContactOwnCompanyBranding>> {
    let capabilities = state
        .service
        .load_capabilities(session.tenant_id, session.id)
        .await?;
    if !capabilities
        .iter()
        .any(|c| c == caps::SETTINGS_MANAGE_COMPANY_BRANDING)
    {
        return Err(AppError::Forbidden(format!(
            "Missing required capability: {}",
            caps::SETTINGS_MANAGE_COMPANY_BRANDING
        )));
    }
    let out = state
        .service
        .load_own_company_branding(session.tenant_id, session.company_id)
        .await?;
    Ok(Json(out))
}

/// MAPPS-618 (mokosh-branding prompt 002): PATCH the caller's own
/// Company branding. Same wire shape (JSONB subset + explicit nulls
/// to clear) as `PUT /tenants/{id}` uses for the tenant side
/// (PMS-758). Server derives the target Company from the session
/// (`companies/self`) so the caller can only ever paint their own
/// Company. Gated on `settings:manage_company_branding`.
async fn update_own_company_branding(
    State(state): State<ContactRouterState>,
    RequireContactAuth(session): RequireContactAuth,
    Json(branding): Json<serde_json::Value>,
) -> AppResult<Json<ContactOwnCompanyBranding>> {
    let capabilities = state
        .service
        .load_capabilities(session.tenant_id, session.id)
        .await?;
    if !capabilities
        .iter()
        .any(|c| c == caps::SETTINGS_MANAGE_COMPANY_BRANDING)
    {
        return Err(AppError::Forbidden(format!(
            "Missing required capability: {}",
            caps::SETTINGS_MANAGE_COMPANY_BRANDING
        )));
    }
    if !branding.is_object() {
        return Err(AppError::validation_field(
            "branding",
            "must be an object of branding keys",
        ));
    }
    let out = state
        .service
        .update_own_company_branding(session.tenant_id, session.company_id, &branding)
        .await?;
    Ok(Json(out))
}

/// PMS-935: aggregate dashboard tile grid. Scoped to the signed-in
/// contact's Company; no capability check because the visibility
/// signal here is aggregate counts, not row data - if a Contact
/// can see the underlying tickets / invoices / quotes / contracts
/// via their own list endpoints, they can already count them
/// themselves.
async fn dashboard_summary(
    State(state): State<ContactRouterState>,
    RequireContactAuth(session): RequireContactAuth,
) -> AppResult<Json<ContactDashboardSummary>> {
    let tenant = TenantId::from_trusted(session.tenant_id);
    let summary = state
        .service
        .dashboard_summary(tenant, session.company_id)
        .await?;
    Ok(Json(summary))
}

async fn portal_host(
    State(state): State<ContactRouterState>,
    Path(handle): Path<String>,
) -> AppResult<Json<ContactPortalHostHint>> {
    // mokosh-contact-login prompt 011 (PMS-928): dispatch on the
    // shape of the path segment. All-ASCII-digits parses as a
    // numeric Portal ID; anything else (a legacy Crockford slug, a
    // typo) falls through to the slug lookup. `parse::<i64>` is
    // the discriminator; the range CHECK on `companies.portal_id`
    // is what guarantees a valid Portal ID sits inside 9 digits, so
    // an integer outside that range simply misses the row and 404s.
    let hint = if handle.chars().all(|c| c.is_ascii_digit()) {
        match handle.parse::<i64>() {
            Ok(portal_id) => state.service.resolve_host_by_portal_id(portal_id).await?,
            Err(_) => None,
        }
    } else {
        state.service.resolve_host(&handle).await?
    };
    let hint = hint.ok_or_else(|| AppError::not_found("portal host"))?;
    Ok(Json(hint))
}

/// mokosh-contact-login prompt 011 (PMS-928): the client-side compat
/// redirect endpoint. Returns `{ portal_id }` for a known legacy
/// slug whose Company has been assigned a Portal ID, else 404.
///
/// Enumeration-resistant by construction: an unknown slug and a
/// known-slug-without-a-portal_id both return the same 404 shape.
async fn resolve_slug_to_portal_id(
    State(state): State<ContactRouterState>,
    Path(slug): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let portal_id = state
        .service
        .resolve_slug_to_portal_id(&slug)
        .await?
        .ok_or_else(|| AppError::not_found("portal id"))?;
    Ok(Json(serde_json::json!({ "portal_id": portal_id })))
}

// ============================================================================
// COOKIE HELPERS
// ============================================================================

/// mokosh-contact-login prompt 004: attach a `mokosh:contact_token`
/// cookie carrying the refresh token to a login / refresh response,
/// so the SPA can survive a hard-refresh cold-load (learns from
/// MAPPS-564 pain).
///
/// HttpOnly = JS cannot read it (XSS-resistant). Secure = TLS-only
/// (dev over http will still function because most browsers relax
/// Secure on localhost; production always has TLS). SameSite=Lax =
/// cross-site GET/POST cannot forge it. Path scoped so the cookie
/// only travels on `/api/v1/contact/auth/*` where the refresh
/// endpoint lives.
fn with_refresh_cookie(resp: &ContactLoginResponse, mut into: Response) -> Response {
    add_cookie(
        into.headers_mut(),
        &build_refresh_cookie(&resp.refresh_token),
    );
    into
}

fn build_refresh_cookie(refresh_token: &str) -> String {
    format!(
        "{name}={value}; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/contact/auth; Max-Age={max_age}",
        name = REFRESH_COOKIE_NAME,
        value = refresh_token,
        max_age = REFRESH_COOKIE_MAX_AGE_SECS,
    )
}

fn clear_refresh_cookie() -> String {
    format!(
        "{name}=; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/contact/auth; Max-Age=0",
        name = REFRESH_COOKIE_NAME,
    )
}

fn add_cookie(headers: &mut HeaderMap, cookie: &str) {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        headers.append(header::SET_COOKIE, v);
    }
}
