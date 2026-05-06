//! Build the auth router. Mount under whatever prefix the host
//! application chooses (typically `/`).

use axum::routing::{get, post};
use axum::Router;
use mokosh_auth_oidc::OidcProvider;
use std::sync::Arc;
use url::Url;

use crate::cookies::CookieConfig;
use crate::handlers::{
    auth as auth_h, discovery as disc_h, login_ui as login_h, oidc as oidc_h,
};
use crate::local_auth::LocalAuth;

#[derive(Clone)]
pub struct AuthHttpState {
    pub provider: OidcProvider,
    pub local_auth: Arc<LocalAuth>,
    pub cookie_cfg: CookieConfig,
    /// URL of the OP login UI that `authorize` redirects to when the
    /// user is not authenticated. Hosted by the front-end (mokosh-clients).
    pub login_url: Url,
}

pub fn build_router(state: Arc<AuthHttpState>) -> Router {
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
        .with_state(state)
}
