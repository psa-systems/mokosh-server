//! Build the auth router. Mount under whatever prefix the host
//! application chooses (typically `/`).

use axum::http::{header, Method};
use axum::routing::{get, post};
use axum::Router;
use mokosh_auth_oidc::OidcProvider;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use url::Url;

use crate::cookies::CookieConfig;
use crate::handlers::{
    auth as auth_h, discovery as disc_h, login_ui as login_h, oidc as oidc_h,
};
use crate::local_auth::LocalAuth;
use crate::rate_limit::RateLimiter;

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
        // OP own login UI: HTML form (browser flow).
        .route("/login", get(login_h::login_form).post(login_h::login_submit))
        // JSON API equivalents (used by client SDKs / native apps).
        .route("/v1/auth/login", post(auth_h::login))
        .route("/v1/auth/logout", post(auth_h::logout))
        .layer(cors)
        .with_state(state)
}
