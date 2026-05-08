//! Build the auth router. Mount under whatever prefix the host
//! application chooses (typically `/`).

use axum::http::{header, Method};
use axum::routing::{get, post};
use axum::Router;
use futures_util::future::BoxFuture;
use mokosh_auth_core::{InviteRepository, TenantId};
use mokosh_auth_oidc::OidcProvider;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use url::Url;

use crate::cookies::CookieConfig;
use crate::email::Mailer;
use crate::handlers::{
    auth as auth_h, discovery as disc_h, invites as invites_h, oidc as oidc_h,
};
use crate::local_auth::LocalAuth;
use crate::rate_limit::RateLimiter;

/// Resolve a tenant's display name. Owned by the host app
/// (mokosh-server reads `public.tenants`); the auth-http crate stays
/// schema-agnostic by accepting a closure. Returns `None` for unknown
/// tenant ids; callers fall back to a generic "Mokosh" label.
pub type TenantNameLookup =
    Arc<dyn Fn(TenantId) -> BoxFuture<'static, Option<String>> + Send + Sync>;

#[derive(Clone)]
pub struct AuthHttpState {
    pub provider: OidcProvider,
    pub local_auth: Arc<LocalAuth>,
    pub cookie_cfg: CookieConfig,
    /// URL of the OP login UI that `authorize` redirects to when the
    /// user is not authenticated. Hosted by the front-end (mokosh-clients).
    pub login_url: Url,
    /// In-memory rate limiter for login + token endpoints. Shared
    /// across the request handlers via `Arc`. Phase-1: per-replica.
    pub rate_limiter: Arc<RateLimiter>,
    /// Admin-invite repository (Phase 1 of registration system).
    pub invites: Arc<dyn InviteRepository>,
    /// Outbound email for invites (and future password reset / magic
    /// link). Stub `LogMailer` in dev; `LettreMailer` in prod.
    pub mailer: Arc<dyn Mailer>,
    /// Tenant-name resolver. The auth crates do not own the tenants
    /// table, so the host app injects this closure.
    pub tenant_name: TenantNameLookup,
}

pub fn build_router(state: Arc<AuthHttpState>) -> Router {
    // Permissive CORS on the OIDC surface. These endpoints are
    // designed to be called cross-origin by browser SPAs:
    //   - /.well-known/openid-configuration and jwks.json are public
    //     metadata
    //   - /oauth2/token, /userinfo, /revoke take Authorization headers
    //     and PKCE proofs, never cookies (cross-origin cookie use
    //     would defeat the SPA model anyway)
    // We deliberately do NOT enable allow_credentials, since the OIDC
    // flow uses Bearer tokens. /oauth2/authorize and /oauth2/logout
    // are reached via top-level browser navigation (set_href), not
    // fetch, so they do not need CORS at all but allowing them is
    // harmless. /login is same-origin only.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]);

    Router::new()
        // Discovery
        .route(
            "/.well-known/openid-configuration",
            get(disc_h::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(disc_h::jwks))
        // OIDC
        .route("/oauth2/authorize", get(oidc_h::authorize))
        .route("/oauth2/token", post(oidc_h::token))
        .route("/oauth2/userinfo", get(oidc_h::userinfo))
        .route("/oauth2/revoke", post(oidc_h::revoke))
        .route("/oauth2/logout", get(oidc_h::logout))
        // Local password authentication. The SPA posts here directly and
        // (when supplying `client_id`) gets back a token bundle, so users
        // never see a separate OP-hosted login form. The OIDC authorize
        // endpoint above is kept available for future relying parties; if
        // they hit it without an OP session we currently 404 the
        // login-redirect path - that gets wired to a real RP login screen
        // when the first external RP is onboarded.
        .route("/v1/auth/login", post(auth_h::login))
        .route("/v1/auth/logout", post(auth_h::logout))
        // Admin invites (admin-gated)
        .route(
            "/v1/auth/invites",
            post(invites_h::issue).get(invites_h::list_open),
        )
        .route("/v1/auth/invites/{invite_id}/revoke", post(invites_h::revoke))
        .route("/v1/auth/invites/{invite_id}/resend", post(invites_h::resend))
        // Public token-gated invite endpoints
        .route(
            "/v1/auth/invites/by-token/{token}",
            get(invites_h::read_by_token),
        )
        .route(
            "/v1/auth/invites/by-token/{token}/accept",
            post(invites_h::accept_by_token),
        )
        .layer(cors)
        .with_state(state)
}
