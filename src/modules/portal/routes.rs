//! Portal HTTP routes.
//!
//! Layout intentionally mirrors `auth/routes.rs` so a reader who knows
//! the agent surface can navigate this one. The router returned here
//! is meant to be mounted at `/api/v1/portal` and wrapped in
//! `portal_auth_middleware`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::captcha::{TurnstileError, TurnstileGate};
use super::host_tenant::{portal_origin_from_host, resolve_slug, PortalHostConfig};
use super::middleware::{
    portal_auth_middleware, PortalAuthMiddleware, RequirePortalAuth, RequirePortalSession,
};
use super::rate_limit::{PortalDecisionLimiter, PortalHostLimiter, PortalLoginLimiter};
use super::service::PortalAuthService;
use super::{
    CreatePortalTicketNoteRequest, CreatePortalTicketRequest, CurrentContactMe, PortalApproval,
    PortalApprovalDecisionRequest, PortalAsset, PortalChangePasswordRequest, PortalCompanyContact,
    PortalContract, PortalDashboardResponse, PortalDelegation, PortalDelegationGrantRequest,
    PortalExportJob, PortalForgotPasswordRequest, PortalHostHint, PortalInviteColleagueRequest,
    PortalInviteColleagueResponse, PortalInvoicePaymentsResponse, PortalLoginRequest,
    PortalLogoutRequest, PortalMfaDisableRequest, PortalMfaEnableRequest, PortalMfaEnableResponse,
    PortalMfaSetupRequest, PortalMfaSetupResponse, PortalNotificationsResponse, PortalProject,
    PortalProjectDetail, PortalRefreshRequest, PortalResetPasswordRequest, PortalSearchResponse,
    PortalSessionResponse, PortalSetupPasswordRequest, PortalTicketSlaResponse, PortalTimeEntry,
    ResolvedTenant,
};
use crate::modules::billing::{BillingService, InvoiceFilter, InvoiceResponse, PayInvoiceResponse};
use crate::modules::knowledge_base::{KbArticleResponse, KbService};
use crate::modules::quotes::{
    ClientDecision, PortalQuoteDecisionRequest, QuoteResponse, QuotesService,
};
use crate::modules::tickets::{TicketNoteResponse, TicketResponse, TicketService};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct PortalRouterState {
    pub service: Arc<PortalAuthService>,
    pub tickets: Arc<TicketService>,
    pub kb: Arc<KbService>,
    pub billing: Arc<BillingService>,
    pub quotes: Arc<QuotesService>,
    /// Layered (per-IP + per-(tenant_slug, email)) login rate limiter
    /// (PMS-501). Lives for the lifetime of the router so quota state
    /// survives across requests. The check runs inline at the top of the
    /// `login` handler so the limiter can see both source IP and the
    /// `(tenant_slug, email)` from the deserialized request body.
    pub login_limiter: Arc<PortalLoginLimiter>,
    /// PMS-673: throttles the quote accept / decline routes. Separate from
    /// `login_limiter` so a burst of decisions cannot lock a contact out of
    /// logging back in.
    pub decision_limiter: Arc<PortalDecisionLimiter>,
    /// PMS-729 nice-to-have: per-IP throttle for `GET /portal/host`. The
    /// endpoint is unauthenticated and DB-hitting, so a scanner probing
    /// many Host headers against the same IP could otherwise walk the
    /// tenant list at unlimited RPS. 60/min per IP; a real SPA fires this
    /// once per page load and never trips the bucket.
    pub host_limiter: Arc<PortalHostLimiter>,
    /// PMS-711: SPA origin the invoice "Pay Now" success / cancel return URLs
    /// are built from (the base of the portal invoice pages).
    pub portal_origin: String,
    /// PMS-729: host-to-tenant resolution config. Drives the `PortalHostConfig`
    /// extract_slug call inside the login handler and the `/host` branding
    /// endpoint. When the underlying suffix is empty (feature disabled),
    /// every host lookup returns `None` and the handlers fall back to the
    /// legacy body `tenant_slug` path.
    pub host_config: PortalHostConfig,
    /// PMS-729 phase 2 H8: Cloudflare Turnstile gate for the login
    /// route. Per-IP failure counter that requires a CAPTCHA solve on
    /// the next login attempt once the source IP crosses a threshold
    /// (100 fails/hour by default). Off unless BOTH TURNSTILE_SITE_KEY
    /// + TURNSTILE_SECRET_KEY are set.
    pub captcha: Arc<TurnstileGate>,
}

/// Build the `/api/v1/portal` router. Wires the portal auth middleware
/// at the outermost layer so every handler sees either a valid
/// `PortalAuthState` or the default (unauthenticated) one.
#[allow(clippy::too_many_arguments)]
pub fn portal_routes(
    service: PortalAuthService,
    tickets: TicketService,
    kb: KbService,
    billing: BillingService,
    quotes: QuotesService,
    portal_origin: String,
    host_config: PortalHostConfig,
    captcha: Arc<TurnstileGate>,
) -> Router {
    let state = PortalRouterState {
        service: Arc::new(service.clone()),
        tickets: Arc::new(tickets),
        kb: Arc::new(kb),
        billing: Arc::new(billing),
        quotes: Arc::new(quotes),
        login_limiter: PortalLoginLimiter::new(),
        decision_limiter: PortalDecisionLimiter::new(),
        host_limiter: PortalHostLimiter::new(),
        portal_origin,
        host_config,
        captcha,
    };
    let mw = PortalAuthMiddleware::new(service);

    Router::new()
        // Public: login. No auth required to call this.
        .route("/auth/login", post(login))
        // PMS-729 phase 2 H2: rotate the presented refresh token into a
        // fresh access + refresh pair. Public: the presented refresh
        // token itself is the credential (server-side revocation store
        // means a stolen access token cannot renew after logout).
        .route("/auth/refresh", post(refresh))
        // PMS-729 phase 2 H1: revoke the presented refresh token and
        // every other live token in its rotation chain. Public for the
        // same reason as refresh; the presented token is the credential.
        .route("/auth/logout", post(logout))
        // Public: redeem a setup token to set the initial portal password
        // (PMS-136). No auth: the customer is not yet a logged-in contact;
        // the single-use token IS the credential proving they own the link.
        .route("/auth/setup-password", post(setup_password))
        // PMS-729 phase 2 H3: request a password-reset email. Always
        // 204 (enumeration-resistant). If the (host-derived tenant,
        // email) pair matches a portal contact, a fresh reset token
        // is minted and emailed; otherwise no email is sent.
        .route("/auth/forgot-password", post(forgot_password))
        // PMS-729 phase 2 H3: redeem an emailed reset token to set the
        // new password. Same 204 / 400 / 410 status contract as
        // /auth/setup-password.
        .route("/auth/reset-password", post(reset_password))
        // PMS-729 phase 2 H3: authenticated password change. Requires
        // the current password for re-auth so a stolen access token
        // cannot silently rotate the credential. New password runs
        // through the H5 policy.
        .route("/auth/me/password", put(change_password))
        // PMS-729 phase 2 H4: MFA management. Setup mints a fresh
        // TOTP secret + provisioning URI (does not enable). Enable
        // confirms with a code + mints recovery codes. Disable
        // requires current-password + valid TOTP for re-auth.
        .route("/auth/me/mfa/setup", post(mfa_setup))
        .route("/auth/me/mfa/enable", post(mfa_enable))
        .route("/auth/me/mfa/disable", post(mfa_disable))
        // PMS-729 phase 2 H6: session listing + per-session revoke.
        // GET returns the caller's live refresh tokens (portal
        // sessions) with a `current` flag on the one that minted the
        // caller's access token. DELETE revokes the whole rotation
        // chain of a specific session; refuses when the id matches
        // the caller's own session (self-sign-out is /auth/logout).
        .route("/auth/me/sessions", get(list_sessions))
        .route("/auth/me/sessions/{session_id}", delete(revoke_session))
        // PMS-729: public branding hint. The SPA login page calls this on
        // mount to decide (a) whether to hide the slug input and (b) which
        // MSP name + logo to paint above the credential fields. Returns
        // 404 with an empty body on any resolution miss so the endpoint
        // cannot be used to enumerate live MSPs.
        .route("/host", get(host_hint))
        // Protected: profile + ticket creation. List + get arrive in
        // subsequent commits in this story.
        .route("/auth/me", get(me))
        .route("/tickets", get(list_tickets).post(create_ticket))
        .route("/tickets/{ticket_id}", get(get_ticket))
        // PMS-449: portal ticket comments. GET lists `note_type='public'`
        // notes (internal / resolution / time_entry are filtered server-
        // side). POST accepts a fresh contact-authored comment that the
        // service stamps with `created_by_contact_id` while keeping
        // `created_by_id` pointed at a fallback admin (the column is NOT
        // NULL; the FK is to `users`, not `contacts`).
        .route(
            "/tickets/{ticket_id}/notes",
            get(list_ticket_notes).post(create_ticket_note),
        )
        .route("/invoices", get(list_invoices))
        .route("/invoices/{invoice_id}", get(get_invoice))
        // PMS-711: client-facing "Pay Now". Mints a provider checkout session
        // for the invoice balance and returns its URL for the SPA to redirect
        // to. Company-scoped exactly like `get_invoice`.
        .route("/invoices/{invoice_id}/pay", post(pay_invoice))
        // PMS-673: client-facing quote sign-off. Reads are scoped to the
        // contact's own company and to statuses that were actually issued;
        // accept / decline are the client's decision and are the only way
        // a quote reaches `accepted` / `declined`.
        .route("/quotes", get(list_quotes))
        .route("/quotes/{quote_id}", get(get_quote))
        .route("/quotes/{quote_id}/accept", post(accept_quote))
        .route("/quotes/{quote_id}/decline", post(decline_quote))
        .route("/kb", get(list_kb))
        // Portal-scoped single-article read. Enforces the same
        // status='published' + visibility check the list feed uses, so a
        // stored-but-not-visible article 404s rather than confirming its
        // existence to the caller.
        .route("/kb/{id}", get(get_kb_article))
        // PMS-729 phase 2 §7 slice A / I17: portal home dashboard.
        // Aggregated counts + latest activity for the caller's company,
        // scoped by the JWT-verified tenant + company. Fixed set of
        // four cards per D17; no query params.
        .route("/dashboard", get(get_dashboard))
        // PMS-729 phase 2 §7 slice A / I10: SLA visibility on portal
        // ticket detail. Returns first-response + resolution targets and
        // actuals, plus the computed on-track / warning / breached label
        // shared with the agent side.
        .route("/tickets/{ticket_id}/sla", get(get_ticket_sla))
        // PMS-729 phase 2 §7 slice A / I11: payment history on portal
        // invoice detail. Payment ledger newest-first, safe subset
        // (no internal notes, no gateway_response blobs).
        .route(
            "/invoices/{invoice_id}/payments",
            get(list_invoice_payments),
        )
        // PMS-729 phase 2 §7 slice A / I14: portal-scoped search.
        // Query param `q`. Every query enforces
        // `company_id = contact.company_id` and, for KB, honors the
        // same public / client_specific visibility rules the list
        // endpoint uses. NEVER cross-company (D18).
        .route("/search", get(portal_search))
        // PMS-729 phase 2 §7 slice B / I12: portal notifications inbox.
        // Contact-scoped list of the newest 50 in_app rows with an
        // unread count; PUT marks one read.
        .route("/notifications", get(list_notifications))
        .route(
            "/notifications/{notification_id}/read",
            put(mark_notification_read),
        )
        // PMS-729 phase 2 §7 slice C: read-only company-scoped views.
        .route("/assets", get(list_portal_assets))
        .route("/assets/{asset_id}", get(get_portal_asset))
        .route("/contracts", get(list_portal_contracts))
        .route("/contracts/{contract_id}", get(get_portal_contract))
        .route("/time-entries", get(list_portal_time_entries))
        .route("/projects", get(list_portal_projects))
        .route("/projects/{project_id}", get(get_portal_project))
        // PMS-729 phase 2 §7 slice D.
        .route("/approvals", get(list_portal_approvals))
        .route(
            "/approvals/{approval_id}/decide",
            post(decide_portal_approval),
        )
        .route(
            "/company/contacts",
            get(list_company_contacts).post(invite_colleague),
        )
        .route(
            "/company/delegations",
            get(list_portal_delegations).post(grant_portal_delegation),
        )
        .route(
            "/company/delegations/{delegation_id}",
            delete(revoke_portal_delegation),
        )
        .route("/export", post(request_portal_export))
        .route("/export/{job_id}", get(get_portal_export))
        .route("/export/{job_id}/download", get(download_portal_export))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            mw,
            portal_auth_middleware,
        ))
}

/// Portal login. Rate-limited per `(source IP, (tenant_slug, lowercased
/// email))` at 20/min per IP + 5/min per account; over-quota returns 429
/// with a `Retry-After` header (PMS-501). The check runs inline because
/// tower middleware cannot read the JSON body without buffering it. A
/// persistent failed-attempt lockout lives in `PortalAuthService::login`
/// and surfaces here as `AppError::RateLimited` (429) as well.
///
/// PMS-729: resolves the tenant slug from the request Host FIRST, then
/// gates against the body's optional `tenant_slug`. Missing or
/// mismatching pairs collapse to `AppError::Unauthorized` so the
/// response envelope is byte-identical to a wrong-password rejection and
/// the endpoint cannot be used to enumerate MSPs.
async fn login(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<PortalLoginRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    let resolved_slug =
        resolve_login_slug(&state, &headers, request.tenant_slug.as_deref()).await?;

    if let Err(retry_after) = state
        .login_limiter
        .check(addr.ip(), &resolved_slug, &request.email)
    {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "rate_limited",
                "message": "Too many login attempts, please try again later",
                "retry_after_seconds": retry_after,
            })),
        )
            .into_response();
        let h = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
            h.insert(header::RETRY_AFTER, v);
        }
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(resp);
    }

    // PMS-729 phase 2 H8: gate against the Turnstile counter for this
    // IP. When the per-IP failure count is under the threshold this is
    // a no-op; over the threshold, the SPA has to supply a valid
    // `captcha_token` to proceed. Off (both env keys unset) = allow.
    match state
        .captcha
        .gate(addr.ip(), request.captcha_token.as_deref())
        .await
    {
        Ok(()) => {}
        Err(TurnstileError::Required) => {
            return Ok(captcha_challenge_response(
                "CAPTCHA_REQUIRED",
                "Please solve the CAPTCHA challenge and try again.",
                state.captcha.site_key(),
            ));
        }
        Err(TurnstileError::Invalid) => {
            return Ok(captcha_challenge_response(
                "CAPTCHA_INVALID",
                "The CAPTCHA response was rejected. Please try again.",
                state.captcha.site_key(),
            ));
        }
    }

    let ua = user_agent_from(&headers);
    // Post-code-review finding #5: derive the origin from the request
    // so the login-location alert email's "review sessions" link points
    // at the tenant's own subdomain on per-tenant deploys.
    let per_request_origin = portal_origin_from_host(
        &state.host_config,
        headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim),
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
        &state.portal_origin,
    );
    match state
        .service
        .login(
            &resolved_slug,
            &request.email,
            &request.password,
            request.mfa_code.as_deref(),
            request.recovery_code.as_deref(),
            ua.as_deref(),
            Some(addr.ip()),
            Some(&per_request_origin),
        )
        .await
    {
        Ok(resp) => Ok(Json(resp).into_response()),
        Err(e) => {
            // PMS-729 phase 2 H8: tick the per-IP failure counter on
            // 401 so the next attempt from this IP is more likely to
            // trip the challenge. Only ticks on credential-adjacent
            // failures (401), NOT on rate-limit (429) or upstream
            // errors, so a random 500 does not lock down a legit IP.
            if matches!(e, AppError::Unauthorized) {
                state.captcha.record_failure(addr.ip()).await;
            }
            Err(e)
        }
    }
}

/// PMS-729 phase 2 H8: render the 403 challenge response the SPA
/// picks up to render the Turnstile widget. `site_key` is embedded in
/// the body so the SPA does not need a separate `GET /config` round
/// trip to know which key to configure the widget with.
fn captcha_challenge_response(code: &str, message: &str, site_key: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": {
                "code": code,
                "message": message,
                "captcha": {
                    "provider": "turnstile",
                    "site_key": site_key,
                },
            },
        })),
    )
        .into_response()
}

/// PMS-729 phase 2 H2: rotate a refresh token. Public route because the
/// presented token IS the credential; the SPA holds no other identifier.
/// Any failure (unknown token, expired, revoked, replay-detected) folds
/// to 401 so the wire shape does not leak whether the token was ever
/// valid, still valid, or freshly detected as stolen.
async fn refresh(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<PortalRefreshRequest>,
) -> Result<Response, AppError> {
    request.validate()?;
    let ua = user_agent_from(&headers);
    let resp = state
        .service
        .refresh_access_token(&request.refresh_token, ua.as_deref(), Some(addr.ip()))
        .await?;
    Ok(Json(resp).into_response())
}

/// PMS-729 phase 2 H1: revoke a refresh token and its rotation chain.
/// Idempotent + enumeration-resistant: an unknown or already-revoked
/// token still returns 204 so a caller cannot probe whether a specific
/// token id ever existed. The access token itself expires on its own;
/// this route revokes the ability to renew.
async fn logout(
    State(state): State<PortalRouterState>,
    Json(request): Json<PortalLogoutRequest>,
) -> Result<StatusCode, AppError> {
    request.validate()?;
    state.service.logout(&request.refresh_token).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// PMS-729 phase 2 H3: request a password-reset email. Always returns
/// 204 whether the email matches a known portal contact or not so the
/// response shape cannot be used to enumerate portal accounts. When it
/// DOES match, the service returns the mint info and the handler
/// dispatches a `portal.password_reset` email carrying the link.
async fn forgot_password(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<PortalForgotPasswordRequest>,
) -> Result<StatusCode, AppError> {
    request.validate()?;

    // Resolve the tenant the same way the login handler does: Host
    // (X-Forwarded-Host) first, body-slug fallback. Missing or invalid
    // slug fails silently (204) - same enumeration-resistance rule.
    let Ok(resolved_slug) =
        resolve_login_slug(&state, &headers, request.tenant_slug.as_deref()).await
    else {
        return Ok(StatusCode::NO_CONTENT);
    };

    let ua = user_agent_from(&headers);
    let Some(issue) = state
        .service
        .request_password_reset(
            &resolved_slug,
            &request.email,
            Some(addr.ip()),
            ua.as_deref(),
        )
        .await?
    else {
        // Unknown email OR non-portal contact. Still 204.
        return Ok(StatusCode::NO_CONTENT);
    };

    // Dispatch the reset email via the notifications queue. On dev
    // (LogMailer) this ends up in tracing output; on staging + prod
    // (SmtpMailer) it lands in the customer's inbox. The reset URL
    // uses the portal origin the router was constructed with (either
    // the CLIENT_ORIGIN default or a portal-host-derived value per
    // PMS-729). Best-effort: a send failure does NOT propagate to the
    // client (still 204) so enumeration resistance holds.
    // Post-code-review finding #5: build the reset link off the
    // request's own host when the portal-host feature is on, so
    // per-tenant subdomain deploys email a link at
    // `{slug}.client.<apex>` instead of the single CLIENT_ORIGIN
    // fallback (which does not resolve to a tenant on those hosts).
    let per_request_origin = portal_origin_from_host(
        &state.host_config,
        headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim),
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
        &state.portal_origin,
    );
    let link = format!(
        "{}/portal/reset-password?token={}",
        per_request_origin.trim_end_matches('/'),
        issue.token
    );
    if let Err(e) = state
        .service
        .dispatch_password_reset_email(&issue, &link)
        .await
    {
        tracing::warn!(?e, "portal password_reset email dispatch failed");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// PMS-729 phase 2 H3: redeem a password-reset token. 204 on happy
/// path, 400 on expired / unknown / malformed, 410 on replay.
/// Password strength is enforced by `utils::password_policy` (H5) and
/// runs AFTER token verification so a bad-token attempt does not
/// surface as "password too weak". A successful reset revokes every
/// live refresh token for the contact as a side effect.
async fn reset_password(
    State(state): State<PortalRouterState>,
    Json(request): Json<PortalResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    request.validate()?;
    state
        .service
        .reset_password(&request.token, &request.password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// PMS-729 phase 2 H3: authenticated password change. `RequirePortalAuth`
/// identifies the caller from the access token, so the body only carries
/// `current_password` (for re-auth so a stolen access token cannot
/// silently rotate the credential) and `new_password`.
async fn change_password(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Json(request): Json<PortalChangePasswordRequest>,
) -> Result<StatusCode, AppError> {
    request.validate()?;
    state
        .service
        .change_password(
            contact.id,
            contact.tenant_id,
            &request.current_password,
            &request.new_password,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// PMS-729 phase 2 H4: start portal MFA enrollment. Requires an
/// authenticated session; mints a fresh TOTP secret and stores it on
/// the contact row without flipping `portal_mfa_enabled`. The response
/// carries the base32 secret + `otpauth://` provisioning URI so the
/// SPA can render a QR code.
async fn mfa_setup(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Json(request): Json<PortalMfaSetupRequest>,
) -> Result<Json<PortalMfaSetupResponse>, AppError> {
    request.validate()?;
    let resp = state
        .service
        .start_mfa_enrollment(contact.id, contact.tenant_id, &request.current_password)
        .await?;
    Ok(Json(resp))
}

/// PMS-729 phase 2 H4: confirm MFA enrollment. Verifies a live TOTP
/// code against the secret set by `/setup`, flips `portal_mfa_enabled`
/// to TRUE, and returns 10 single-use recovery codes (surfaced once;
/// server stores only Argon2id hashes).
async fn mfa_enable(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Json(request): Json<PortalMfaEnableRequest>,
) -> Result<Json<PortalMfaEnableResponse>, AppError> {
    request.validate()?;
    let resp = state
        .service
        .enable_mfa(
            contact.id,
            contact.tenant_id,
            &request.code,
            &request.current_password,
        )
        .await?;
    Ok(Json(resp))
}

/// PMS-729 phase 2 H4: disable MFA. Requires the current password AND
/// a valid TOTP code (defence-in-depth: a stolen access token cannot
/// silently disable the second factor). Clears the secret + recovery
/// codes on success.
async fn mfa_disable(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Json(request): Json<PortalMfaDisableRequest>,
) -> Result<StatusCode, AppError> {
    request.validate()?;
    state
        .service
        .disable_mfa(
            contact.id,
            contact.tenant_id,
            &request.current_password,
            &request.code,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// PMS-729 phase 2 H6: list the caller's live portal sessions.
/// Each row is a live (unrevoked, unexpired) refresh token; the
/// `current` flag marks the one that minted the caller's own access
/// token so the SPA can highlight "this browser".
async fn list_sessions(
    State(state): State<PortalRouterState>,
    RequirePortalSession { contact, sid }: RequirePortalSession,
) -> Result<Json<Vec<PortalSessionResponse>>, AppError> {
    let sessions = state
        .service
        .list_sessions(contact.id, contact.tenant_id, sid)
        .await?;
    Ok(Json(sessions))
}

/// PMS-729 phase 2 H6: revoke one of the caller's other sessions.
/// Refuses when `session_id` matches the caller's own sid (returns
/// 400 with a message pointing at `/portal/auth/logout`). Unknown or
/// foreign session ids silently succeed (enumeration-resistant,
/// mirrors the `/portal/auth/logout` posture).
async fn revoke_session(
    State(state): State<PortalRouterState>,
    RequirePortalSession { contact, sid }: RequirePortalSession,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    state
        .service
        .revoke_session(session_id, contact.id, contact.tenant_id, sid)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// PMS-729 phase 2 helper: pull the User-Agent header as an owned
/// string, capping the length to prevent a huge value from bloating the
/// `portal_refresh_tokens.user_agent` column. Falls back to `None` when
/// the header is absent or fails UTF-8 (an invalid UA is not worth
/// failing the login for).
fn user_agent_from(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::USER_AGENT)?.to_str().ok()?;
    Some(raw.chars().take(500).collect())
}

/// PMS-729 helper: pull the resolved slug out of the (host, body) pair.
/// Any failure mode collapses to `AppError::Unauthorized` so the caller
/// treats it exactly like a wrong password. Split out so the login
/// handler stays readable and the `/host` endpoint can reuse the
/// host-lookup half.
async fn resolve_login_slug(
    state: &PortalRouterState,
    headers: &HeaderMap,
    body_slug: Option<&str>,
) -> Result<String, AppError> {
    let host_tenant = lookup_host_tenant(state, headers).await?;
    resolve_slug(host_tenant.as_ref(), body_slug).map_err(|_| AppError::Unauthorized)
}

/// PMS-729: read the request's effective host, run it through the
/// configured slug extractor, and (if the label survives) resolve to an
/// active tenant row. Returns `None` on every negative case (feature
/// disabled, host miss, malformed label, unknown or inactive tenant) so
/// the caller only distinguishes `Some` from `None`.
///
/// Header priority: `X-Forwarded-Host` (first value only) beats `Host`.
/// Under a reverse proxy that rewrites the `Host` header for its backend
/// (Dioxus 0.7.7's dev proxy, most CDN edges, some load balancers) the
/// original browser-visible host lives on `X-Forwarded-Host`; without
/// this fallback the extractor would see the proxy's own hostname and
/// fail closed even for a legitimate `{slug}.client.<apex>` request.
/// Reading the FIRST value on the header respects the RFC 7239 chain
/// (leftmost is the original client-visible host).
async fn lookup_host_tenant(
    state: &PortalRouterState,
    headers: &HeaderMap,
) -> Result<Option<ResolvedTenant>, AppError> {
    let Some(host_hdr) = effective_host(headers) else {
        return Ok(None);
    };
    let Some(slug) = state.host_config.extract_slug(host_hdr) else {
        return Ok(None);
    };
    state.service.resolve_host_tenant(&slug).await
}

/// PMS-729: pull the browser-visible host out of the request. Prefers
/// `X-Forwarded-Host` (first value, comma-split) so the dev Dioxus
/// proxy + production reverse proxies + CDN edges all thread through
/// consistently. Falls back to the plain `Host` header when the
/// forwarded one is absent, so a direct client hitting the server also
/// works.
fn effective_host(headers: &HeaderMap) -> Option<&str> {
    if let Some(fwd) = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
    {
        let first = fwd.split(',').next().unwrap_or(fwd).trim();
        if !first.is_empty() {
            return Some(first);
        }
    }
    headers.get(header::HOST).and_then(|v| v.to_str().ok())
}

/// PMS-729: public branding hint for the SPA login page. Returns 200
/// with the tenant's display name + full [`PortalBranding`] surface
/// (flattened at the JSON layer) when the Host resolves to an active
/// tenant; 404 with an empty body on every other outcome so an unknown
/// or malformed host is indistinguishable from a legitimately-not-portal
/// host.
///
/// Nice-to-have: per-IP rate limit (60/min via `PortalHostLimiter`) so
/// this pre-auth DB-hitting endpoint cannot be script-walked to
/// enumerate slugs at unlimited RPS. Over-quota returns 429 with a
/// `Retry-After` header and the same JSON envelope shape as the login
/// route's rate-limit response.
async fn host_hint(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Err(retry_after) = state.host_limiter.check(addr.ip()) {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "rate_limited",
                "message": "Too many portal host lookups, please try again later",
                "retry_after_seconds": retry_after,
            })),
        )
            .into_response();
        let h = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
            h.insert(header::RETRY_AFTER, v);
        }
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(resp);
    }
    let tenant = lookup_host_tenant(&state, &headers)
        .await?
        .ok_or(AppError::NotFound("portal host".to_string()))?;
    Ok(Json(PortalHostHint {
        name: tenant.display_name,
        branding: tenant.branding,
    })
    .into_response())
}

/// PMS-729 phase 2 §7 slice A / I17: portal home dashboard payload.
/// Delegates to `PortalAuthService::dashboard` which forces the company
/// scope from the authenticated `CurrentContact`.
async fn get_dashboard(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<PortalDashboardResponse>> {
    // SAFETY (PMS-285): verified contact-JWT claims. `dashboard`
    // pins every query to `contact.company_id`.
    let payload = state
        .service
        .dashboard(contact.tenant(), contact.company_id)
        .await?;
    Ok(Json(payload))
}

/// PMS-729 phase 2 §7 slice A / I10: SLA card payload for a portal
/// ticket. Cross-company / unknown ids surface as 404 (`NotFound`),
/// same posture as `get_ticket`, so the endpoint never confirms the
/// existence of another company's ticket.
async fn get_ticket_sla(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<PortalTicketSlaResponse>> {
    let payload = state
        .service
        .ticket_sla(contact.tenant(), contact.company_id, ticket_id)
        .await?;
    Ok(Json(payload))
}

/// PMS-729 phase 2 §7 slice C / I3: portal assets.
async fn list_portal_assets(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<Vec<PortalAsset>>> {
    Ok(Json(
        state
            .service
            .list_portal_assets(contact.tenant(), contact.company_id)
            .await?,
    ))
}

async fn get_portal_asset(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(asset_id): Path<Uuid>,
) -> AppResult<Json<PortalAsset>> {
    Ok(Json(
        state
            .service
            .get_portal_asset(contact.tenant(), contact.company_id, asset_id)
            .await?,
    ))
}

/// PMS-729 phase 2 §7 slice C / I4: portal contracts.
async fn list_portal_contracts(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<Vec<PortalContract>>> {
    Ok(Json(
        state
            .service
            .list_portal_contracts(contact.tenant(), contact.company_id)
            .await?,
    ))
}

async fn get_portal_contract(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(contract_id): Path<Uuid>,
) -> AppResult<Json<PortalContract>> {
    Ok(Json(
        state
            .service
            .get_portal_contract(contact.tenant(), contact.company_id, contract_id)
            .await?,
    ))
}

/// Query parameters for `GET /portal/time-entries`. All optional; empty
/// query mirrors the pre-filter behaviour (first page of 100).
#[derive(Debug, serde::Deserialize)]
struct PortalTimeEntriesQuery {
    #[serde(default)]
    from: Option<chrono::NaiveDate>,
    #[serde(default)]
    to: Option<chrono::NaiveDate>,
    #[serde(default)]
    page: Option<i64>,
    #[serde(default)]
    per_page: Option<i64>,
}

/// PMS-729 phase 2 §7 slice C / I5: portal time entries.
async fn list_portal_time_entries(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(query): Query<PortalTimeEntriesQuery>,
) -> AppResult<Json<Vec<PortalTimeEntry>>> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(100);
    Ok(Json(
        state
            .service
            .list_portal_time_entries(
                contact.tenant(),
                contact.company_id,
                query.from,
                query.to,
                page,
                per_page,
            )
            .await?,
    ))
}

/// PMS-729 phase 2 §7 slice C / I6: portal projects.
async fn list_portal_projects(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<Vec<PortalProject>>> {
    Ok(Json(
        state
            .service
            .list_portal_projects(contact.tenant(), contact.company_id)
            .await?,
    ))
}

async fn get_portal_project(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(project_id): Path<Uuid>,
) -> AppResult<Json<PortalProjectDetail>> {
    Ok(Json(
        state
            .service
            .get_portal_project(contact.tenant(), contact.company_id, project_id)
            .await?,
    ))
}

// --------- Slice D handlers ---------

async fn list_portal_approvals(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<Vec<PortalApproval>>> {
    Ok(Json(
        state
            .service
            .list_portal_approvals(contact.tenant(), contact.id)
            .await?,
    ))
}

async fn decide_portal_approval(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(approval_id): Path<Uuid>,
    Json(body): Json<PortalApprovalDecisionRequest>,
) -> AppResult<StatusCode> {
    state
        .service
        .decide_portal_approval(
            contact.tenant(),
            contact.id,
            approval_id,
            &body.decision,
            body.decision_notes.as_deref(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_company_contacts(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<Vec<PortalCompanyContact>>> {
    Ok(Json(
        state
            .service
            .list_company_contacts(contact.tenant(), contact.company_id, contact.id)
            .await?,
    ))
}

/// PMS-729 follow-up: portal-side invite-a-colleague. Adds a new
/// portal-visible contact under the caller's own company + tenant
/// (both from the verified JWT, never body input) and dispatches the
/// same `auth.welcome` setup-link email an agent-side grant fires.
/// The response echoes only the new contact id; the setup token is
/// emailed rather than returned.
async fn invite_colleague(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    headers: HeaderMap,
    Json(request): Json<PortalInviteColleagueRequest>,
) -> AppResult<Json<PortalInviteColleagueResponse>> {
    // Per-request origin so the setup-link email points at the
    // tenant's own subdomain (`acme.client.<apex>`) on per-tenant
    // deploys - matches the login-location alert path (finding #5).
    let per_request_origin = portal_origin_from_host(
        &state.host_config,
        headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim),
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
        &state.portal_origin,
    );
    let id = state
        .service
        .invite_colleague(
            contact.tenant(),
            contact.company_id,
            contact.id,
            &request.first_name,
            &request.last_name,
            &request.email,
            &per_request_origin,
        )
        .await?;
    Ok(Json(PortalInviteColleagueResponse { id }))
}

async fn list_portal_delegations(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<Vec<PortalDelegation>>> {
    Ok(Json(
        state
            .service
            .list_portal_delegations(contact.tenant(), contact.id)
            .await?,
    ))
}

async fn grant_portal_delegation(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Json(body): Json<PortalDelegationGrantRequest>,
) -> AppResult<(StatusCode, Json<PortalDelegation>)> {
    let scope = if body.scope.is_null() {
        serde_json::json!({})
    } else {
        body.scope
    };
    let d = state
        .service
        .grant_portal_delegation(
            contact.tenant(),
            contact.company_id,
            contact.id,
            body.delegatee_contact_id,
            scope,
            body.expires_at,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(d)))
}

async fn revoke_portal_delegation(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(delegation_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state
        .service
        .revoke_portal_delegation(contact.tenant(), contact.id, delegation_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn request_portal_export(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<(StatusCode, Json<PortalExportJob>)> {
    let job = state
        .service
        .request_portal_export(contact.tenant(), contact.company_id, contact.id)
        .await?;
    Ok((StatusCode::CREATED, Json(job)))
}

async fn get_portal_export(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(job_id): Path<Uuid>,
) -> AppResult<Response> {
    let mut job = state
        .service
        .get_portal_export(contact.tenant(), contact.id, job_id)
        .await?;
    // PMS-729 phase 2 §7 slice D / I15: bundle URLs expire at D19's
    // 7-day mark. Once past that, blank the URL client-side and mark
    // the status so the SPA can render "expired, please re-request".
    // The row stays server-side for audit.
    let expired = job
        .expires_at
        .map(|exp| exp <= chrono::Utc::now())
        .unwrap_or(false);
    if expired {
        job.status = "expired".to_string();
        job.signed_url = None;
    } else if job.status == "ready" {
        // Server hands the SPA the portal-authed download path; the
        // SPA hits it with the bearer via `get_portal_authed_bytes`
        // (a plain <a href> would 401 because the bearer only lives
        // in WASM memory).
        job.signed_url = Some(format!("/portal/export/{job_id}/download"));
    }
    Ok((StatusCode::OK, Json(job)).into_response())
}

/// PMS-729 phase 2 §7 slice D / I15 follow-up: download the JSON bundle
/// for a caller's ready export. `AppError::NotFound` when the job id
/// is cross-contact or unknown; 410 Gone when the row exists but the
/// bundle is not yet ready OR has expired past its 7-day TTL.
async fn download_portal_export(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(job_id): Path<Uuid>,
) -> AppResult<Response> {
    let bundle = state
        .service
        .get_portal_export_bundle(contact.tenant(), contact.id, job_id)
        .await?;
    let Some(bundle) = bundle else {
        return Ok((StatusCode::GONE, "Bundle unavailable").into_response());
    };
    let body = serde_json::to_vec_pretty(&bundle).unwrap_or_else(|_| b"{}".to_vec());
    let filename = format!("mokosh-portal-export-{job_id}.json");
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                    .unwrap_or(HeaderValue::from_static("attachment")),
            ),
        ],
        body,
    )
        .into_response())
}

/// PMS-729 phase 2 §7 slice B / I12: portal inbox list. Contact-scoped
/// via the JWT-verified `CurrentContact`; a caller cannot enumerate
/// another contact's inbox.
/// Query parameters for `GET /portal/notifications`. Both are optional;
/// omitting them returns the first page of 20 (bell menu default).
#[derive(Debug, serde::Deserialize)]
struct PortalNotificationsQuery {
    #[serde(default)]
    page: Option<i64>,
    #[serde(default)]
    per_page: Option<i64>,
}

async fn list_notifications(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(query): Query<PortalNotificationsQuery>,
) -> AppResult<Json<PortalNotificationsResponse>> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    let payload = state
        .service
        .list_portal_inbox(contact.tenant(), contact.id, page, per_page)
        .await?;
    Ok(Json(payload))
}

/// PMS-729 phase 2 §7 slice B / I12: mark one portal inbox row read.
/// Contact-scoped; a cross-contact id returns 404.
async fn mark_notification_read(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(notification_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state
        .service
        .mark_portal_notification_read(contact.tenant(), contact.id, notification_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// PMS-729 phase 2 §7 slice A / I11: payment ledger for one of the
/// caller's invoices. Cross-company / unknown invoice ids surface as
/// 404, matching `get_invoice`.
async fn list_invoice_payments(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<PortalInvoicePaymentsResponse>> {
    let payload = state
        .service
        .list_invoice_payments(contact.tenant(), contact.company_id, invoice_id)
        .await?;
    Ok(Json(payload))
}

/// PMS-729 phase 2 §7 slice A / I14: portal-scoped grouped search.
/// Query params: `q` (required, trimmed; blank returns the empty
/// default). Company scope is forced from `RequirePortalAuth`, never
/// user input.
#[derive(serde::Deserialize)]
struct PortalSearchQuery {
    #[serde(default)]
    q: String,
}

async fn portal_search(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(PortalSearchQuery { q }): Query<PortalSearchQuery>,
) -> AppResult<Json<PortalSearchResponse>> {
    let payload = state
        .service
        .portal_search(contact.tenant(), contact.company_id, &q)
        .await?;
    Ok(Json(payload))
}

async fn me(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
) -> AppResult<Json<CurrentContactMe>> {
    // MFA flag is a DB read rather than a JWT claim so it stays
    // consistent with the next request the moment the customer flips
    // it on/off; caching it on the token would leave the SPA
    // showing "Enable MFA" on a session that already has it.
    let mfa_enabled = state
        .service
        .contact_mfa_enabled(contact.tenant_id, contact.id)
        .await
        .unwrap_or(false);
    Ok(Json(CurrentContactMe {
        id: contact.id,
        tenant_id: contact.tenant_id,
        company_id: contact.company_id,
        email: contact.email,
        first_name: contact.first_name,
        last_name: contact.last_name,
        mfa_enabled,
    }))
}

/// Redeem a setup token and set the contact's portal password (PMS-136).
/// Returns 204 on success; the service maps a replayed token to 410 and an
/// expired/invalid one to 400.
async fn setup_password(
    State(state): State<PortalRouterState>,
    Json(request): Json<PortalSetupPasswordRequest>,
) -> AppResult<StatusCode> {
    request.validate()?;
    state
        .service
        .setup_password(&request.token, &request.password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_invoices(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<InvoiceResponse>>> {
    // PMS-33 has landed: serve the contact's company invoices. The
    // company scope is forced from the authenticated `CurrentContact`
    // (never a query param), so a contact only ever sees its own
    // company's invoices.
    let filter = InvoiceFilter {
        company_id: Some(contact.company_id),
        ..Default::default()
    };
    // SAFETY (PMS-285): `contact.tenant_id` is a verified claim from the portal
    // JWT (`RequirePortalAuth`), i.e. the caller's own authenticated tenant.
    // Portal runs on contact sessions, not `CurrentUser`, so it cannot use the
    // `TenantScoped` extractor; `from_trusted` is the sanctioned bridge (see the
    // KB feed note below for the full rationale).
    let (items, total) = state
        .billing
        .list_invoices(contact.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_invoice(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(invoice_id): Path<Uuid>,
) -> AppResult<Json<InvoiceResponse>> {
    // Read within the contact's tenant, then enforce the company scope
    // in code: an invoice belonging to another company in the same
    // tenant returns 404 (not 403) so the portal never confirms the
    // existence of another company's invoice.
    // SAFETY (PMS-285): `contact.tenant_id` is a verified portal-JWT claim
    // (`RequirePortalAuth`), the caller's own authenticated tenant; portal
    // cannot use `TenantScoped`, so `from_trusted` is the sanctioned bridge
    // (see KB feed note below). The company scope is enforced in code afterward.
    let invoice = state
        .billing
        .get_invoice(contact.tenant(), invoice_id)
        .await?;
    if invoice.company_id != contact.company_id {
        return Err(crate::utils::error::AppError::NotFound(
            "Invoice".to_string(),
        ));
    }
    Ok(Json(invoice))
}

/// PMS-711: client-facing "Pay Now". Mints a provider checkout session for the
/// invoice's outstanding balance and returns its URL. The company scope is
/// enforced first (a cross-company invoice is a 404, same posture as
/// `get_invoice`); the service then rejects a void / fully-paid invoice or a
/// tenant with no active gateway.
async fn pay_invoice(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(invoice_id): Path<Uuid>,
    headers: HeaderMap,
) -> AppResult<Json<PayInvoiceResponse>> {
    // SAFETY (PMS-285): `contact.tenant()` wraps a verified portal-JWT claim,
    // the caller's own authenticated tenant. Portal runs on contact sessions,
    // not `CurrentUser`, so it cannot use `TenantScoped`; `from_trusted` is the
    // sanctioned bridge. The company scope is enforced in code below.
    let invoice = state
        .billing
        .get_invoice(contact.tenant(), invoice_id)
        .await?;
    if invoice.company_id != contact.company_id {
        return Err(AppError::NotFound("Invoice".to_string()));
    }

    // Post-code-review finding #5: same per-request origin derivation
    // as forgot_password. A per-tenant subdomain deploy needs Stripe to
    // return the customer to `{slug}.client.<apex>/portal/invoices/...`
    // not the single CLIENT_ORIGIN fallback.
    let per_request_origin = portal_origin_from_host(
        &state.host_config,
        headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim),
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
        &state.portal_origin,
    );
    let base = per_request_origin.trim_end_matches('/');
    let success_url = format!("{base}/portal/invoices/{invoice_id}?paid=1");
    let cancel_url = format!("{base}/portal/invoices/{invoice_id}");
    let session = state
        .billing
        .create_invoice_checkout_session(contact.tenant(), invoice_id, &success_url, &cancel_url)
        .await?;
    Ok(Json(PayInvoiceResponse {
        checkout_url: session.url,
    }))
}

/// Portal-scoped single KB article read. Enforces the same publish +
/// visibility rules the feed uses; a stored-but-not-visible article
/// returns 404 rather than confirming its existence outside the
/// caller's scope.
async fn get_kb_article(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(article_id): Path<Uuid>,
) -> AppResult<Json<KbArticleResponse>> {
    // SAFETY (PMS-285): `contact.tenant()` wraps a verified portal-JWT
    // claim, the caller's own authenticated tenant. Portal cannot use
    // `TenantScoped`; `from_trusted` is the sanctioned bridge (same
    // rationale as `list_kb`).
    let article = state
        .kb
        .get_portal_article(contact.tenant(), contact.company_id, article_id)
        .await?;
    Ok(Json(article))
}

async fn list_kb(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbArticleResponse>>> {
    // Portal-visible KB feed (PMS-79 / PMS-84). Returns only
    // `status = 'published'` articles that are `visibility = 'public'`
    // OR `client_specific` with the caller's company listed in
    // `company_ids`. The company scope comes from the authenticated
    // contact's JWT claim (`CurrentContact.company_id`), populated by
    // `portal_auth_middleware`, so a client cannot widen it.
    // SAFETY (PMS-139): `contact.tenant_id` is a verified claim from the
    // portal JWT (`RequirePortalAuth`), not user input. Portal runs on
    // contact sessions rather than `CurrentUser`, so it cannot use the
    // `TenantScoped` extractor; `from_trusted` is the sanctioned bridge
    // until the portal surface gets its own scoping pass.
    let (items, total) = state
        .kb
        .list_portal_articles_for_company(contact.tenant(), contact.company_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_ticket(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<TicketResponse>> {
    // SAFETY (PMS-261): `contact.tenant_id` and `contact.company_id` are
    // verified claims from the portal JWT (`RequirePortalAuth`), not user
    // input. Portal runs on contact sessions rather than `CurrentUser`, so it
    // cannot use the `TenantScoped` extractor; `from_trusted` is the sanctioned
    // bridge. `get_portal_ticket` scopes by both tenant and company, so a
    // contact can only read its own company's ticket within its own tenant.
    let resp = state
        .tickets
        .get_portal_ticket(contact.tenant(), contact.company_id, ticket_id)
        .await?;
    Ok(Json(resp))
}

async fn list_tickets(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketResponse>>> {
    // SAFETY (PMS-261): verified contact-JWT claims (`RequirePortalAuth`), not
    // user input; portal cannot use `TenantScoped`. `list_portal_tickets`
    // scopes by both tenant and company, so the feed is confined to the
    // contact's own company within its own tenant.
    let (tickets, total) = state
        .tickets
        .list_portal_tickets(contact.tenant(), contact.company_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        tickets,
        &pagination,
        total,
    )))
}

async fn create_ticket(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Json(request): Json<CreatePortalTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    request.validate()?;
    // SAFETY (PMS-261): verified contact-JWT claims (`RequirePortalAuth`), not
    // user input; portal cannot use `TenantScoped`. `create_portal_ticket`
    // writes under `contact.tenant_id` / `contact.company_id`, so a contact can
    // only create a ticket inside its own company and tenant.
    let resp = state
        .tickets
        .create_portal_ticket(
            contact.tenant(),
            contact.company_id,
            contact.id,
            request.title,
            request.description,
            request.priority_id,
            request.type_id,
        )
        .await?;
    Ok(Json(resp))
}

/// PMS-449: list the public comments on one of the contact's own
/// company's tickets. Server-side filters by `note_type='public'` so
/// internal agent back-channel never leaks to the customer. Cross-
/// company access surfaces as 404 (same posture as `get_ticket`).
async fn list_ticket_notes(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(ticket_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketNoteResponse>>> {
    // SAFETY (PMS-261/PMS-449): verified contact-JWT claims, not user input.
    // The service scopes by both tenant and company, so a guessed ticket id
    // from another company yields the same 404 a missing one would.
    let (notes, total) = state
        .tickets
        .list_portal_ticket_notes(contact.tenant(), contact.company_id, ticket_id, &pagination)
        .await?;
    let responses: Vec<TicketNoteResponse> = notes
        .into_iter()
        .map(|n| TicketNoteResponse {
            id: n.id,
            note_type: n.note_type,
            content: n.content,
            is_email_sent: n.is_email_sent,
            created_by_id: n.created_by_id,
            created_by_name: n.created_by_name.unwrap_or_default(),
            created_by_contact_id: n.created_by_contact_id,
            created_at: n.created_at,
        })
        .collect();
    Ok(Json(PaginatedResponse::from_params(
        responses,
        &pagination,
        total,
    )))
}

/// PMS-449: portal contact adds a comment on one of their own
/// company's tickets. `note_type` is forced to `public` server-
/// side; the customer cannot accidentally write an internal note.
async fn create_ticket_note(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(ticket_id): Path<Uuid>,
    Json(request): Json<CreatePortalTicketNoteRequest>,
) -> AppResult<Json<TicketNoteResponse>> {
    request.validate()?;
    let note = state
        .tickets
        .create_portal_ticket_note(
            contact.tenant(),
            contact.company_id,
            contact.id,
            ticket_id,
            request.content,
        )
        .await?;
    Ok(Json(TicketNoteResponse {
        id: note.id,
        note_type: note.note_type,
        content: note.content,
        is_email_sent: note.is_email_sent,
        created_by_id: note.created_by_id,
        created_by_name: note.created_by_name.unwrap_or_default(),
        created_by_contact_id: note.created_by_contact_id,
        created_at: note.created_at,
    }))
}

// ============================================================================
// PMS-673: client-facing quote sign-off.
// ============================================================================

async fn list_quotes(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<QuoteResponse>>> {
    // The company scope is forced from the authenticated `CurrentContact`,
    // never a query param, so a contact only ever sees its own company's
    // quotes. The service further restricts to issued statuses.
    // SAFETY (PMS-285): `contact.tenant()` wraps a verified portal-JWT
    // claim, the caller's own authenticated tenant; portal runs on contact
    // sessions rather than `CurrentUser`, so it cannot use `TenantScoped`
    // and `from_trusted` is the sanctioned bridge (see the invoice + KB
    // notes above).
    let (items, total) = state
        .quotes
        .list_quotes_for_company(contact.tenant(), contact.company_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_quote(
    State(state): State<PortalRouterState>,
    RequirePortalAuth(contact): RequirePortalAuth,
    Path(quote_id): Path<Uuid>,
) -> AppResult<Json<QuoteResponse>> {
    // A quote belonging to another company, or one not yet issued, comes
    // back 404 rather than 403 so the portal never confirms that it
    // exists. Same posture as `get_invoice`.
    let quote = state
        .quotes
        .get_quote_for_company(contact.tenant(), contact.company_id, quote_id)
        .await?;
    Ok(Json(quote))
}

async fn accept_quote(
    state: State<PortalRouterState>,
    addr: ConnectInfo<SocketAddr>,
    auth: RequirePortalAuth,
    ctx: crate::modules::audit::AuditCtx,
    path: Path<Uuid>,
    body: Option<Json<PortalQuoteDecisionRequest>>,
) -> Result<Response, AppError> {
    decide(state, addr, auth, ctx, path, body, true).await
}

async fn decline_quote(
    state: State<PortalRouterState>,
    addr: ConnectInfo<SocketAddr>,
    auth: RequirePortalAuth,
    ctx: crate::modules::audit::AuditCtx,
    path: Path<Uuid>,
    body: Option<Json<PortalQuoteDecisionRequest>>,
) -> Result<Response, AppError> {
    decide(state, addr, auth, ctx, path, body, false).await
}

/// Shared body of accept / decline. The two routes differ only in the
/// outcome they record, so the rate-limit check, validation, and audit
/// context handling live in one place.
///
/// The JSON body is optional: accepting with nothing to say is the common
/// case, and requiring `{}` would be a needless 415 for that caller.
async fn decide(
    State(state): State<PortalRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    RequirePortalAuth(contact): RequirePortalAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(quote_id): Path<Uuid>,
    body: Option<Json<PortalQuoteDecisionRequest>>,
    accept: bool,
) -> Result<Response, AppError> {
    let request = body.map(|Json(b)| b).unwrap_or_default();
    request.validate()?;

    if let Err(retry_after) = state.decision_limiter.check(addr.ip(), contact.id) {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "rate_limited",
                "message": "Too many quote decisions, please try again shortly",
                "retry_after_seconds": retry_after,
            })),
        )
            .into_response();
        let h = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
            h.insert(header::RETRY_AFTER, v);
        }
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(resp);
    }

    let decision = ClientDecision {
        company_id: contact.company_id,
        contact_id: contact.id,
        accept,
        notes: request.notes,
    };
    let quote = state
        .quotes
        .decide_quote(contact.tenant(), quote_id, &decision, &ctx)
        .await?;
    Ok(Json(quote).into_response())
}
