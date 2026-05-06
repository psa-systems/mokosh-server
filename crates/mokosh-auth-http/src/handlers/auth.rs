//! `/v1/auth/*` handlers: login, logout, first-run setup.

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cookies::{clear_op_session_cookie, set_op_session_cookie};
use crate::errors::HttpError;
use crate::extractors::CurrentOpSession;
use crate::local_auth::LocalLoginRequest;
use crate::router::AuthHttpState;

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub tenant_id: String,
}

pub async fn login(
    State(st): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    Json(req): Json<LocalLoginRequest>,
) -> Result<Response, HttpError> {
    let ip = Some(addr.ip());
    if let Err(rl) = st.rate_limiter.check_login(
        crate::rate_limit::LoginScope::Json,
        ip,
        &req.email,
    ) {
        tracing::warn!(
            target: "mokosh_auth.rate_limit",
            ip = %addr.ip(),
            email = %req.email,
            scope = "login_json",
            "rate limit exceeded"
        );
        return Ok(rl.into_response());
    }
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let session = st.local_auth.login(req, ip, ua).await?;

    let cookie = set_op_session_cookie(&st.cookie_cfg, session.sid.clone(), st.provider.cfg.op_session_ttl);
    let body = LoginResponse {
        user_id: session.user_id.0.to_string(),
        tenant_id: session.tenant_id.0.to_string(),
    };
    Ok((jar.add(cookie), Json(body)).into_response())
}

pub async fn logout(
    State(st): State<Arc<AuthHttpState>>,
    jar: CookieJar,
    session: Result<CurrentOpSession, HttpError>,
) -> Response {
    if let Ok(CurrentOpSession(s)) = session {
        let _ = st
            .provider
            .sessions
            .revoke(s.id, st.provider.clock.now())
            .await;
    }
    let cleared = jar.remove(clear_op_session_cookie(&st.cookie_cfg));
    (cleared, StatusCode::NO_CONTENT).into_response()
}
