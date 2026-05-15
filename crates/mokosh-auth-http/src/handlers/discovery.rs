//! `/.well-known/openid-configuration` and `/.well-known/jwks.json`.

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use std::sync::Arc;

use crate::router::AuthHttpState;

pub async fn openid_configuration(State(st): State<Arc<AuthHttpState>>) -> impl IntoResponse {
    let doc = mokosh_auth_oidc::openid_configuration(&st.provider.cfg.issuer);
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        Json(doc),
    )
}

pub async fn jwks(State(st): State<Arc<AuthHttpState>>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        // The JWKS document is pre-built by the key set at load time, so
        // serving it is just a clone of the cached value.
        Json(st.provider.keys.jwks().clone()),
    )
}
