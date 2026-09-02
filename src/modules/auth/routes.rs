//! Authentication API routes

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    rate_limit, ApiKeyResponse, AuthService, ChangePasswordRequest, CompleteOnboardingRequest,
    CreateApiKeyRequest, CreateApiKeyResponse, CreateUserRequest, ForgotPasswordRequest,
    ListUsersFilter, LoginRequest, MfaDisableRequest, MfaEnableRequest, MfaEnableResponse,
    MfaSetupResponse, RefreshTokenRequest, RefreshTokenResponse, ResetPasswordRequest, SessionInfo,
    UpdateUserRequest, UserResponse,
};
use crate::modules::auth::middleware::{RequireAuth, RequireAuthState, RequireManager};
use crate::modules::auth::TenantScoped;
use crate::utils::error::{rate_limited_response, AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};
use mokosh_types::auth::MembershipView;

/// Application state for auth routes
#[derive(Clone)]
pub struct AuthRouterState {
    pub auth_service: Arc<AuthService>,
    /// Layered (per-IP + per-email) login rate limiter (PMS-4 AC2 / F2).
    /// Lives for the lifetime of the router so quota state survives
    /// across requests. The check happens inline at the top of the
    /// `login` handler so the limiter can see both source IP and the
    /// email from the deserialized request body.
    pub login_limiter: Arc<rate_limit::AuthRateLimiter>,
    /// Layered (per-IP + per-email) limiter for `/forgot-password` (PMS-680).
    /// A separate instance from `login_limiter` with its own (lower) quotas and
    /// buckets, so reset requests and logins never consume each other's quota.
    /// Checked inline in the `forgot_password` handler for the same reason as
    /// login (the email lives in the request body).
    pub forgot_password_limiter: Arc<rate_limit::AuthRateLimiter>,
    /// Failure-counted (per-IP + per-user-id) limiter for the password re-auth
    /// on `/me/password` and `/me/mfa/disable` (PMS-881, audit F6). ONE
    /// instance shared by both routes: they re-check the same credential, so
    /// grinding it through one after exhausting the other must not hand the
    /// attacker a fresh budget. Checked inline in each handler, before the
    /// service call that compares the password.
    pub reauth_limiter: Arc<rate_limit::ReauthRateLimiter>,
}

/// Create the auth router
pub fn auth_routes(auth_service: AuthService) -> Router {
    let state = AuthRouterState {
        auth_service: Arc::new(auth_service),
        // Login: 20/min per IP (NAT'd offices), 5/min per email (account cap).
        login_limiter: rate_limit::AuthRateLimiter::new(20, 5),
        // Forgot-password: rarer than login, so tighter. 10/min per IP,
        // 3/min per email - enough for a fumbling user, caps reset-email
        // bombing of a known address (PMS-680).
        forgot_password_limiter: rate_limit::AuthRateLimiter::new(10, 3),
        // Re-auth: 10/min per IP, 5/min per user. Only FAILED re-auths are
        // counted, and these are interactive settings screens, so a legitimate
        // user mistyping their password twice never comes near it.
        reauth_limiter: rate_limit::ReauthRateLimiter::new(10, 5),
    };

    Router::new()
        // Public routes. Rate limit for `/login` runs inline at the top
        // of the handler (see `login` below) so the limiter can key on
        // `(ip, email)` not just `ip`.
        .route("/login", post(login))
        // MAPPS-492 (MAPPS-474 phase 3): completes a `needs_selection`
        // login by trading the short-lived identity_token + a chosen
        // tenant_id for a full scoped session.
        .route("/select-tenant", post(select_tenant))
        // MAPPS-494 (MAPPS-474 phase 5): switch the current session to
        // another tenant the identity holds a membership in. Bearer
        // required; the switch re-mints access + refresh tokens with the
        // new tid + mid so subsequent requests scope to the picked tenant.
        .route("/switch-tenant/{tenant_id}", post(switch_tenant))
        .route("/logout", post(logout))
        // PMS-880: sign out everywhere. Authenticated like the protected
        // routes below (it needs the caller's identity), grouped here with its
        // single-session sibling because the two are one feature.
        .route("/logout-all", post(logout_all))
        .route("/refresh", post(refresh_token))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
        // MAPPS-552: SetPasswordPage reads this on mount to render
        // "Set your password for [Client Name]" instead of a generic
        // heading. Public (token IS the credential). 404 on unknown /
        // expired token so an attacker cannot enumerate valid tokens
        // via this surface.
        .route(
            "/set-password/context/{token}",
            axum::routing::get(set_password_context),
        )
        // PMS-837: no `/google` mounts. The popup sign-in flow was retired as
        // unconsumed; see the module doc in `mod.rs`.
        // Protected routes
        .route("/me", get(get_current_user))
        .route("/me", put(update_current_user))
        // MAPPS-491 (MAPPS-474 phase 2): every active membership the
        // authenticated identity holds. Populated by the middleware so
        // the handler is a projection over `AuthState.memberships`.
        .route("/memberships", get(list_my_memberships))
        // PMS-752: let the onboarding screen finish. See the handler.
        .route("/me/complete-onboarding", post(complete_onboarding))
        .route("/me/password", put(change_password))
        .route("/me/sessions", get(get_sessions))
        .route("/me/sessions/{session_id}", delete(delete_session))
        // MFA
        .route("/me/mfa/setup", post(start_mfa_enrollment))
        .route("/me/mfa/enable", post(enable_mfa))
        .route("/me/mfa/disable", post(disable_mfa))
        // Personal API keys
        .route("/me/api-keys", get(list_api_keys))
        .route("/me/api-keys", post(create_api_key))
        .route("/me/api-keys/{key_id}", delete(revoke_api_key))
        // PMS-921: the staff directory. Any authenticated user of the tenant,
        // unlike the user-management routes below. Placed apart from them on
        // purpose: it is a different audience and a different projection, and
        // grouping it with `/users` invites somebody to "tidy" it under the
        // same guard.
        .route("/directory", get(list_directory))
        // User management (admin only)
        .route("/users", get(list_users))
        .route("/users", post(create_user))
        .route("/users/{user_id}", get(get_user))
        .route("/users/{user_id}", put(update_user))
        .with_state(state)
}

/// Login endpoint. Rate-limited per `(source IP, lowercased email)`
/// at 20/min per IP + 5/min per email; over-quota returns 429 with
/// a `Retry-After` header. The check has to run inline because tower
/// middleware cannot read the JSON body without buffering it.
async fn login(
    State(state): State<AuthRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    if let Err(retry_after) = state.login_limiter.check(addr.ip(), &request.email) {
        return Ok(rate_limited_response(
            retry_after,
            "Too many login attempts, please try again later",
        ));
    }

    // PMS-587: record the real client IP (from the forwarded header behind
    // Traefik), not the proxy peer address.
    let ip_address = Some(
        crate::utils::client_ip::extract_client_ip(
            addr.ip(),
            &headers,
            crate::utils::client_ip::trusted_proxies(),
        )
        .to_string(),
    );
    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // MAPPS-492 (MAPPS-474 phase 3): identity-first branch. When the
    // caller still has NO tenant hint after the MAPPS-473 host
    // derivation ran, drop into the email-only login flow: the server
    // resolves the identity by email + password, then either
    // auto-scopes (single membership), returns a picker
    // (`needs_selection`), or returns setup (`needs_setup`). Callers
    // that DO supply a tenant hint (existing tests, MAPPS-473
    // auto-resolved hosts, dev slug typing) keep taking the
    // tenant-scoped `AuthService::login` path unchanged.
    let has_tenant_hint = request.tenant_id.is_some()
        || !request
            .tenant_slug
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty();
    let response = if has_tenant_hint {
        match state
            .auth_service
            .login(&request, ip_address, user_agent)
            .await
        {
            Ok(response) => response,
            // PMS-773: the persistent second-factor lockout knows exactly when it
            // lifts, so it answers with the same Retry-After contract as the
            // limiter above instead of a bare 429.
            Err(AppError::RateLimited {
                retry_after_seconds: Some(retry_after),
            }) => {
                return Ok(rate_limited_response(
                    retry_after,
                    "Too many failed verification codes, please try again later",
                ))
            }
            Err(other) => return Err(other),
        }
    } else {
        state
            .auth_service
            .authenticate_identity_first(&request, ip_address, user_agent)
            .await?
    };

    Ok(Json(response).into_response())
}

/// MAPPS-492 (MAPPS-474 phase 3): finish a `needs_selection` login.
/// Consumes an identity token minted by the login handler above and
/// returns a full scoped session for the caller-chosen tenant.
async fn select_tenant(
    State(state): State<AuthRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<mokosh_types::auth::SelectTenantRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    let ip_address = Some(
        crate::utils::client_ip::extract_client_ip(
            addr.ip(),
            &headers,
            crate::utils::client_ip::trusted_proxies(),
        )
        .to_string(),
    );
    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let response = state
        .auth_service
        .select_tenant_for_identity(
            &request.identity_token,
            request.tenant_id,
            ip_address,
            user_agent,
        )
        .await?;
    Ok(Json(response).into_response())
}

/// MAPPS-494 (MAPPS-474 phase 5): switch the caller's active session to
/// a different tenant they hold a membership in. Verifies membership
/// from the pre-populated `AuthState.memberships` (phase-2 enrich pass),
/// then delegates to the shared `mint_session_for_membership` primitive.
///
/// Returns the same `LoginResponse` shape as the login handler so the
/// client's install_session path handles the response unchanged.
async fn switch_tenant(
    State(state): State<AuthRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RequireAuthState(auth_state): RequireAuthState,
    axum::extract::Path(target_tenant_id): axum::extract::Path<Uuid>,
) -> Result<Response, AppError> {
    // Verify the caller holds an ACTIVE membership in the target tenant.
    // Reading from AuthState instead of re-querying the DB: the enrich
    // pass in `auth_middleware` already populated `memberships` for us.
    let has_membership = auth_state
        .memberships
        .iter()
        .any(|m| m.tenant_id == target_tenant_id && m.status == "active");
    if !has_membership {
        return Err(AppError::NotFound(
            "No active membership in the requested tenant".to_string(),
        ));
    }

    let caller = auth_state.user.as_ref().ok_or(AppError::Unauthorized)?;

    let ip_address = Some(
        crate::utils::client_ip::extract_client_ip(
            addr.ip(),
            &headers,
            crate::utils::client_ip::trusted_proxies(),
        )
        .to_string(),
    );
    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let response = state
        .auth_service
        .mint_session_for_membership(target_tenant_id, &caller.email, ip_address, user_agent)
        .await?;
    Ok(Json(response).into_response())
}

/// Logout endpoint
async fn logout(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> AppResult<()> {
    // Extract session ID from token
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Ok(claims) = state.auth_service.decode_token(token) {
                    state.auth_service.logout(claims.sid).await?;
                }
            }
        }
    }

    // Record the logout (PMS-117 AC3).
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // Out-of-band on its own tenant-scoped tx so the RLS GUC is set; a
    // log-write failure must not fail the logout. PMS-256.
    if let Ok(mut tx) = state
        .auth_service
        .db()
        .begin_with_tenant(user.tenant_id)
        .await
    {
        let _ = crate::modules::audit::audit_auth_event(
            &mut *tx,
            user.tenant_id,
            Some(user.id),
            crate::modules::audit::AuditAction::Logout,
            // PMS-587: real client IP behind Traefik, not the proxy peer.
            Some(
                crate::utils::client_ip::extract_client_ip(
                    addr.ip(),
                    &headers,
                    crate::utils::client_ip::trusted_proxies(),
                )
                .to_string(),
            ),
            ua,
        )
        .await;
        let _ = tx.commit().await;
    }

    Ok(())
}

/// Sign out everywhere (PMS-880). Deletes every `user_sessions` row for the
/// caller, so the refresh capability of every device is gone AND, via the
/// MAPPS-531 `sid` check in `ensure_user_and_tenant_active`, every access token
/// they hold is refused on its next request. This is the compromise-recovery
/// path: `logout` sheds one device, this sheds all of them.
///
/// The caller's own bearer dies with the rest, which is the point.
async fn logout_all(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> AppResult<()> {
    state
        .auth_service
        .logout_all(user.tenant_id, user.id)
        .await?;

    // Record it as a logout, exactly as the single-session path does (PMS-117 AC3).
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // Out-of-band on its own tenant-scoped tx so the RLS GUC is set; a
    // log-write failure must not fail the sign-out (the sessions are already
    // gone, and refusing here would tell the caller the opposite). PMS-256.
    // Suppressed, but not silently: the failure is logged with its cause, so a
    // missing audit row is explainable rather than invisible.
    let audited = async {
        let mut tx = state
            .auth_service
            .db()
            .begin_with_tenant(user.tenant_id)
            .await?;
        crate::modules::audit::audit_auth_event(
            &mut *tx,
            user.tenant_id,
            Some(user.id),
            crate::modules::audit::AuditAction::Logout,
            // PMS-587: real client IP behind Traefik, not the proxy peer.
            Some(
                crate::utils::client_ip::extract_client_ip(
                    addr.ip(),
                    &headers,
                    crate::utils::client_ip::trusted_proxies(),
                )
                .to_string(),
            ),
            ua,
        )
        .await?;
        tx.commit().await?;
        Ok::<(), AppError>(())
    }
    .await;
    if let Err(e) = audited {
        tracing::warn!(
            error = %e,
            user = %user.id,
            "sign-out everywhere succeeded but its audit row was not written"
        );
    }

    Ok(())
}

/// Refresh token endpoint
async fn refresh_token(
    State(state): State<AuthRouterState>,
    Json(request): Json<RefreshTokenRequest>,
) -> AppResult<Json<RefreshTokenResponse>> {
    let response = state
        .auth_service
        .refresh_token(&request.refresh_token)
        .await?;

    Ok(Json(response))
}

/// Forgot password endpoint
async fn forgot_password(
    State(state): State<AuthRouterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<ForgotPasswordRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    // PMS-680: throttle per (IP, email) so a known address cannot be
    // reset-email bombed. Runs inline (like login) because the email is in the
    // request body. Over quota returns 429 + Retry-After; under quota the
    // silent-success semantics below are unchanged.
    if let Err(retry_after) = state
        .forgot_password_limiter
        .check(addr.ip(), &request.email)
    {
        return Ok(rate_limited_response(
            retry_after,
            "Too many password reset requests, please try again later",
        ));
    }

    state
        .auth_service
        .request_password_reset(request.tenant_id, &request.email)
        .await?;
    Ok(StatusCode::OK.into_response())
}

/// Reset password endpoint
async fn reset_password(
    State(state): State<AuthRouterState>,
    Json(request): Json<ResetPasswordRequest>,
) -> AppResult<()> {
    request.validate()?;
    state.auth_service.reset_password(&request).await?;
    Ok(())
}

/// MAPPS-552: return the tenant name + slug for the client-admin
/// welcome flow so the SPA's `SetPasswordPage` can render a heading
/// like "Set your password for Acme Co". Token IS the credential -
/// no auth extractor. 404 for any invalid / expired / redeemed token
/// so the shape does not enumerate valid tokens to an attacker.
#[derive(serde::Serialize)]
struct SetPasswordContext {
    tenant_name: String,
    tenant_slug: String,
}

async fn set_password_context(
    State(state): State<AuthRouterState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> AppResult<Json<SetPasswordContext>> {
    let (tenant_name, tenant_slug) = state.auth_service.set_password_context(&token).await?;
    Ok(Json(SetPasswordContext {
        tenant_name,
        tenant_slug,
    }))
}

/// Get current user endpoint
async fn get_current_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<UserResponse>> {
    let full_user = state
        .auth_service
        .get_user_by_id(user.tenant_id, user.id)
        .await?;
    Ok(Json(full_user.into()))
}

/// MAPPS-491 (MAPPS-474 phase 2): every active membership the caller
/// holds. Populated by the middleware, so this is a projection over
/// `AuthState.memberships`; no query runs in the handler. Client's
/// `use_memberships_loader` (mokosh-clients/src/hooks/auth.rs:299)
/// calls this endpoint on login and on switcher open.
async fn list_my_memberships(
    RequireAuthState(state): RequireAuthState,
) -> AppResult<Json<Vec<MembershipView>>> {
    Ok(Json(state.memberships))
}

/// Update current user endpoint
async fn update_current_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    request.validate()?;

    // Users can't change their own role or status
    let sanitized_request = UpdateUserRequest {
        role: None,
        status: None,
        ..request
    };

    let updated = state
        .auth_service
        .update_user(user.tenant_id, user.id, &sanitized_request, &ctx)
        .await?;

    Ok(Json(updated.into()))
}

/// PMS-752: mark the caller's profile as onboarded.
///
/// Since PMS-512 `profile_completed_at` was stamped in exactly one place:
/// `upsert_user_from_oidc`, on a login whose bunyip claims carry both names.
/// That left the SPA's fallback onboarding screen unable to complete itself.
/// It collects what it can, posts here, and the guard stops firing.
///
/// Idempotent by `COALESCE`, so a double submit or a replayed request keeps the
/// original timestamp rather than moving it. Nothing here trusts a body: the
/// only thing being asserted is "this user has been through onboarding", and
/// the caller is the user.
async fn complete_onboarding(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    body: Option<Json<CompleteOnboardingRequest>>,
) -> AppResult<Json<UserResponse>> {
    // Body is optional so a client that only needs to stamp the
    // timestamp can POST with no body (empty payload rejected by
    // Axum's Json extractor would 415 the caller; falling through to
    // an Option lets the empty case be graceful).
    let (first_name, last_name) = match body {
        Some(Json(req)) => {
            req.validate()?;
            (req.first_name, req.last_name)
        }
        None => (None, None),
    };
    let updated = state
        .auth_service
        .mark_profile_completed(
            user.tenant_id,
            user.id,
            first_name.as_deref(),
            last_name.as_deref(),
        )
        .await?;
    Ok(Json(updated.into()))
}

/// Source IP for the re-auth buckets (PMS-881). The socket peer behind Traefik
/// is the proxy on every request, so keying on it alone would make one global
/// bucket in which any user's failures throttle everybody; `extract_client_ip`
/// walks the forwarded chain and falls back to the peer for a direct client,
/// which cannot spoof it (PMS-587).
fn reauth_client_ip(addr: SocketAddr, headers: &HeaderMap) -> std::net::IpAddr {
    crate::utils::client_ip::extract_client_ip(
        addr.ip(),
        headers,
        crate::utils::client_ip::trusted_proxies(),
    )
}

/// True when this error is `change_password`'s rejection of the submitted
/// current password, rather than a mistyped new password or a failing
/// database. Only a rejected re-auth spends rate-limit budget (PMS-881), so a
/// user who fumbles the confirmation field is never throttled.
fn is_wrong_current_password(err: &AppError) -> bool {
    matches!(err, AppError::Validation { errors, .. }
        if errors.iter().any(|e| e.field == "current_password"))
}

/// Change password endpoint. The current-password re-auth is rate limited per
/// IP and per user (PMS-881, audit F6), sharing one budget with
/// `disable_mfa`, so a stolen session cannot grind the password at full rate.
async fn change_password(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    let ip = reauth_client_ip(addr, &headers);
    if let Err(retry_after) = state.reauth_limiter.check(ip, user.id) {
        return Ok(rate_limited_response(
            retry_after,
            "Too many failed password attempts, please try again later",
        ));
    }

    match state
        .auth_service
        .change_password(user.tenant_id, user.id, &request)
        .await
    {
        Ok(()) => Ok(StatusCode::OK.into_response()),
        Err(err) => {
            if is_wrong_current_password(&err) {
                state.reauth_limiter.record_failure(ip, user.id);
            }
            Err(err)
        }
    }
}

/// Get user sessions
async fn get_sessions(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<SessionInfo>>> {
    // Get current session ID from token
    let current_session_id = if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                state
                    .auth_service
                    .decode_token(token)
                    .map(|c| c.sid)
                    .unwrap_or(Uuid::nil())
            } else {
                Uuid::nil()
            }
        } else {
            Uuid::nil()
        }
    } else {
        Uuid::nil()
    };

    let (sessions, total) = state
        .auth_service
        .get_user_sessions(user.tenant_id, user.id, current_session_id, &pagination)
        .await?;

    Ok(Json(PaginatedResponse::from_params(
        sessions,
        &pagination,
        total,
    )))
}

/// Delete a session
async fn delete_session(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Path(session_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .auth_service
        .delete_session(user.id, session_id)
        .await?;
    Ok(())
}

/// Begin TOTP enrollment. Generates and persists a fresh secret;
/// `mfa_enabled` is not flipped until the user confirms via
/// `POST /me/mfa/enable`.
async fn start_mfa_enrollment(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<MfaSetupResponse>> {
    let resp = state
        .auth_service
        .start_mfa_enrollment(user.tenant_id, user.id)
        .await?;
    Ok(Json(resp))
}

/// Confirm TOTP enrollment by verifying one code; flips `mfa_enabled`
/// and returns 10 single-use recovery codes shown ONCE to the user
/// (PMS-4 AC3). The client is responsible for displaying them
/// somewhere durable; the server only persists their hashes.
async fn enable_mfa(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<MfaEnableRequest>,
) -> AppResult<Json<MfaEnableResponse>> {
    request.validate()?;
    let resp = state
        .auth_service
        .enable_mfa(user.tenant_id, user.id, &request.code)
        .await?;
    Ok(Json(resp))
}

/// Disable MFA. Requires re-auth with the current password so a stolen
/// session cannot weaken the account quietly. Zeroes the user's
/// recovery-code set. The re-auth is rate limited per IP and per user out of
/// the same budget as `change_password` (PMS-881, audit F6): the two check the
/// same credential, so failures on one count against the other.
async fn disable_mfa(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<MfaDisableRequest>,
) -> Result<Response, AppError> {
    request.validate()?;

    let ip = reauth_client_ip(addr, &headers);
    if let Err(retry_after) = state.reauth_limiter.check(ip, user.id) {
        return Ok(rate_limited_response(
            retry_after,
            "Too many failed password attempts, please try again later",
        ));
    }

    match state
        .auth_service
        .disable_mfa(user.tenant_id, user.id, &request.password)
        .await
    {
        Ok(()) => Ok(StatusCode::OK.into_response()),
        Err(err) => {
            // `disable_mfa` reports only the password check as `Unauthorized`;
            // a missing user or a passwordless account is a different variant.
            if matches!(err, AppError::Unauthorized) {
                state.reauth_limiter.record_failure(ip, user.id);
            }
            Err(err)
        }
    }
}

/// List the caller's personal API keys. Never includes secret material.
async fn list_api_keys(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ApiKeyResponse>>> {
    let (keys, total) = state
        .auth_service
        .list_api_keys(user.tenant_id, user.id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        keys,
        &pagination,
        total,
    )))
}

/// Mint a new personal API key. The raw key is returned ONCE in the
/// response; callers must store it client-side immediately.
async fn create_api_key(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateApiKeyRequest>,
) -> AppResult<Json<CreateApiKeyResponse>> {
    request.validate()?;
    let resp = state
        .auth_service
        .create_api_key(user.tenant_id, user.id, &request, &ctx)
        .await?;
    Ok(Json(resp))
}

/// Revoke an API key. Scoped to the calling user + tenant.
async fn revoke_api_key(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Path(key_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .auth_service
        .revoke_api_key(user.tenant_id, user.id, key_id)
        .await?;
    Ok(())
}

/// List users (admin / manager only). Supports paginated browsing
/// PMS-921: the tenant's staff, as the minimum needed to name one.
///
/// `RequireAuth`, not `RequireManager`. MAPPS-578 renders `@handle` in Markdown
/// as a resolved person, and it resolved against `GET /auth/users`, which is
/// manager-gated, so a Technician saw every mention as plain text. A KB article
/// is written for technicians and the mentions in it assign ownership, so the
/// reader who most needs to know who is named was the one who could not see it.
///
/// Relaxing `/users` instead was the wrong shape: its `UserResponse` carries
/// role, status, MFA state, login history and phone numbers, so it would have
/// handed every technician a colleague's security posture to solve a name
/// lookup. That gate stays exactly where it is.
async fn list_directory(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<mokosh_types::auth::DirectoryEntry>>> {
    let (entries, total) = state
        .auth_service
        .list_directory(user.tenant(), &pagination)
        .await?;

    Ok(Json(PaginatedResponse::new(
        entries,
        pagination.page,
        pagination.per_page(),
        total,
    )))
}

/// plus optional filters: `q` (substring across email + names),
/// `role`, and `status`. Filter struct derives `Validate` (F9
/// closeout for the auth module).
async fn list_users(
    State(state): State<AuthRouterState>,
    manager: RequireManager,
    Query(filter): Query<ListUsersFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<UserResponse>>> {
    let user = manager.0;
    filter.validate()?;

    let (users, total) = state
        .auth_service
        .list_users(user.tenant_id, &filter, &pagination)
        .await?;

    Ok(Json(PaginatedResponse::new(
        users.into_iter().map(UserResponse::from).collect(),
        pagination.page,
        pagination.per_page(),
        total,
    )))
}

/// Create user (admin only)
async fn create_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    // Check admin permission
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to do that".to_string(),
        ));
    }

    // Role ceiling (PMS-503): a caller may only create a user whose role is at
    // or below their own privilege. Without this an `admin` could mint a
    // `super_admin` (a platform-level account with cross-tenant access).
    if !user.role.can_grant(request.role) {
        return Err(AppError::Forbidden(
            "Cannot create a user with a role above your own".to_string(),
        ));
    }

    request.validate()?;

    let new_user = state
        .auth_service
        .create_user(user.tenant_id, &request, &ctx)
        .await?;

    Ok(Json(new_user.into()))
}

/// Get user by ID (admin or self). PMS-4 AC6: the service binds
/// `tenant_id` so a cross-tenant `user_id` returns 404 here instead
/// of leaking a row.
async fn get_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<UserResponse>> {
    if !user.role.is_admin() && user.id != user_id {
        return Err(AppError::Forbidden(
            "You do not have permission to do that".to_string(),
        ));
    }

    let target_user = state
        .auth_service
        .get_user_by_id(user.tenant_id, user_id)
        .await?;

    Ok(Json(target_user.into()))
}

/// Update user (admin only)
async fn update_user(
    State(state): State<AuthRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to do that".to_string(),
        ));
    }

    // Role ceiling (PMS-503 / PMS-625): a caller may only assign a role at or
    // below their own privilege. `create_user` already gates this, but the
    // update path did not - so a tenant `admin` could elevate any user (or
    // themselves via `PUT /users/{self}`, which is NOT the role-sanitizing
    // `/me` handler) to `super_admin`, a platform-level cross-tenant account.
    // Mirror the create-side check so the ceiling holds on both surfaces.
    if let Some(role) = request.role {
        if !user.role.can_grant(role) {
            return Err(AppError::Forbidden(
                "Cannot assign a role above your own".to_string(),
            ));
        }
    }

    request.validate()?;

    let updated = state
        .auth_service
        .update_user(user.tenant_id, user_id, &request, &ctx)
        .await?;

    Ok(Json(updated.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use axum::body::Body;
    use sqlx::postgres::PgPool;
    use tower::ServiceExt;

    /// PMS-837: the Google OAuth popup surface was retired as unconsumed. This
    /// is the mechanical guard: re-mounting either route turns these 404s into
    /// 200/500 and fails here, so the surface cannot come back unnoticed.
    ///
    /// Routing a miss never touches the database, so the lazy pool is never
    /// connected.
    #[tokio::test]
    async fn google_oauth_routes_stay_unmounted() {
        let pool = PgPool::connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool builds without connecting");
        let router = auth_routes(AuthService::new(
            Database::from_pool(pool),
            "test-secret".to_string(),
        ));

        for uri in ["/google", "/google/callback"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request builds"),
                )
                .await
                .expect("router responds");
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{uri} must stay unmounted (PMS-837)"
            );
        }
    }
}
