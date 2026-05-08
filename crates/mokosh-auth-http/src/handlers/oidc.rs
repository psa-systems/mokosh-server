//! `/oauth2/*` handlers.

use axum::extract::{ConnectInfo, Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use std::net::SocketAddr;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use mokosh_auth_oidc::{
    handle_authorize, handle_logout, handle_token, handle_userinfo, AuthorizeOutcome,
    AuthorizeRequest, LogoutOutcome, LogoutRequest, TokenRequest,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::cookies::OP_SESSION_COOKIE;
use crate::errors::HttpError;
use crate::router::AuthHttpState;

// --- /oauth2/authorize --------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
}

pub async fn authorize(
    State(st): State<Arc<AuthHttpState>>,
    jar: CookieJar,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let req = AuthorizeRequest {
        response_type: q.response_type.unwrap_or_default(),
        client_id: q.client_id.unwrap_or_default(),
        redirect_uri: q.redirect_uri.unwrap_or_default(),
        scope: q.scope.unwrap_or_default(),
        state: q.state.unwrap_or_default(),
        nonce: q.nonce,
        code_challenge: q.code_challenge.unwrap_or_default(),
        code_challenge_method: q.code_challenge_method.unwrap_or_default(),
        prompt: q.prompt,
    };

    // Resolve current OP session from cookie (best effort).
    let current_session = match jar.get(OP_SESSION_COOKIE) {
        Some(c) => match st.provider.sessions.find_by_sid(c.value()).await {
            Ok(Some(s)) if s.is_active(st.provider.clock.now()) => Some(s),
            _ => None,
        },
        None => None,
    };

    match handle_authorize(&st.provider, req, current_session.as_ref()).await {
        AuthorizeOutcome::Redirect { to } => Redirect::to(to.as_str()).into_response(),
        AuthorizeOutcome::NeedsLogin { request } => {
            // Redirect to OP login UI, preserving the original authorize
            // query string so the UI can resume the flow after sign-in.
            let mut url = st.login_url.clone();
            url.query_pairs_mut()
                .append_pair("return_to", &serialize_authorize_query(&request));
            Redirect::to(url.as_str()).into_response()
        }
        AuthorizeOutcome::ErrorPage { error } => HttpError(error).into_response(),
    }
}

fn serialize_authorize_query(req: &AuthorizeRequest) -> String {
    let mut u = url::Url::parse("urn:mokosh:resume").expect("static url");
    u.query_pairs_mut()
        .append_pair("response_type", &req.response_type)
        .append_pair("client_id", &req.client_id)
        .append_pair("redirect_uri", &req.redirect_uri)
        .append_pair("scope", &req.scope)
        .append_pair("state", &req.state)
        .append_pair("code_challenge", &req.code_challenge)
        .append_pair("code_challenge_method", &req.code_challenge_method);
    if let Some(n) = &req.nonce {
        u.query_pairs_mut().append_pair("nonce", n);
    }
    if let Some(p) = &req.prompt {
        u.query_pairs_mut().append_pair("prompt", p);
    }
    u.query().unwrap_or_default().to_string()
}

// --- /oauth2/token ------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Serialize)]
pub struct TokenJson {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

pub async fn token(
    State(st): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(f): Form<TokenForm>,
) -> Result<Response, HttpError> {
    if let Err(rl) = st.rate_limiter.check_token(Some(addr.ip())) {
        tracing::warn!(
            target: "mokosh_auth.rate_limit",
            ip = %addr.ip(),
            scope = "token_endpoint",
            "rate limit exceeded"
        );
        return Ok(rl.into_response());
    }
    let mut creds = mokosh_auth_oidc::client_auth::PresentedClientCredentials {
        client_id: f.client_id.clone(),
        client_secret: f.client_secret.clone(),
        from_basic_header: false,
    };
    // Try HTTP Basic (RFC 6749 prefers this when both are present).
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(s) = auth.to_str() {
            if let Some(rest) = s.strip_prefix("Basic ") {
                if let Ok(decoded) = STANDARD.decode(rest.trim()) {
                    if let Ok(text) = std::str::from_utf8(&decoded) {
                        if let Some((id, secret)) = text.split_once(':') {
                            creds.client_id = Some(
                                urlencoding::decode(id).map(|c| c.into_owned()).unwrap_or(id.to_string()),
                            );
                            creds.client_secret = Some(
                                urlencoding::decode(secret).map(|c| c.into_owned()).unwrap_or(secret.to_string()),
                            );
                            creds.from_basic_header = true;
                        }
                    }
                }
            }
        }
    }

    let req = TokenRequest {
        grant_type: f.grant_type.unwrap_or_default(),
        code: f.code,
        redirect_uri: f.redirect_uri,
        code_verifier: f.code_verifier,
        refresh_token: f.refresh_token,
        scope: f.scope,
        client_credentials: creds,
    };

    let resp = handle_token(&st.provider, req).await?;
    let body = TokenJson {
        access_token: resp.access_token,
        token_type: resp.token_type,
        expires_in: resp.expires_in,
        refresh_token: resp.refresh_token,
        scope: resp.scope,
        id_token: resp.id_token,
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response())
}

// --- /oauth2/userinfo ---------------------------------------------------

pub async fn userinfo(
    State(st): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| HttpError(mokosh_auth_core::AuthError::AccessDenied("missing bearer".into())))?;
    let resp = handle_userinfo(&st.provider, bearer).await?;
    Ok(Json(resp).into_response())
}

// --- /oauth2/revoke -----------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
}

/// RFC 7009 revocation endpoint.
///
/// Per spec we MUST always return 200, regardless of whether the token
/// was known, to prevent token enumeration via timing or status. The
/// best-effort revocation underneath:
///  - SHA-256 the presented token (refresh tokens are stored hashed)
///  - Hand it to `revoke_by_token_hash`, which looks up the family
///    and revokes every token in it
///  - Swallow any storage error
///
/// `token_type_hint` is advisory per RFC 7009 5.1.1.1; we ignore it for
/// now (refresh tokens are the only kind we can revoke server-side).
/// Access tokens are stateless `at+jwt` and expire on their own.
pub async fn revoke(
    State(st): State<Arc<AuthHttpState>>,
    Form(f): Form<RevokeForm>,
) -> StatusCode {
    if let Some(token) = f.token.as_deref().filter(|s| !s.is_empty()) {
        let hash = mokosh_auth_crypto::hash_opaque_token(token);
        let now = st.provider.clock.now();
        match st
            .provider
            .refresh
            .revoke_by_token_hash(hash, "client_revocation", now)
            .await
        {
            Ok(Some(op_sid)) => {
                // The family was bound to an OP session. Kill the
                // session too so the user is genuinely logged out;
                // otherwise the HttpOnly OP cookie would silently
                // re-authorize a future /oauth2/authorize request.
                if let Err(e) = st.provider.sessions.revoke(op_sid, now).await {
                    tracing::warn!("revoke: op_session storage error swallowed: {e}");
                }
            }
            Ok(None) => {} // unknown token (RFC 7009: indistinguishable response)
            Err(e) => {
                // Log but never surface: RFC 7009 demands a 200.
                tracing::warn!("revoke: storage error swallowed: {e}");
            }
        }
    }
    StatusCode::OK
}

// --- /oauth2/logout -----------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

pub async fn logout(
    State(st): State<Arc<AuthHttpState>>,
    jar: CookieJar,
    Query(q): Query<LogoutQuery>,
) -> Response {
    let outcome = handle_logout(
        &st.provider,
        LogoutRequest {
            id_token_hint: q.id_token_hint,
            client_id: q.client_id,
            post_logout_redirect_uri: q.post_logout_redirect_uri,
            state: q.state,
        },
    )
    .await;

    let cleared = jar.remove(crate::cookies::clear_op_session_cookie(&st.cookie_cfg));

    match outcome {
        LogoutOutcome::LoggedOut { redirect_to: Some(to) } => {
            (cleared, Redirect::to(to.as_str())).into_response()
        }
        LogoutOutcome::LoggedOut { redirect_to: None } => {
            (cleared, StatusCode::NO_CONTENT).into_response()
        }
        LogoutOutcome::NeedsConfirmation => {
            (cleared, StatusCode::NO_CONTENT).into_response()
        }
        LogoutOutcome::Error(err) => HttpError(err).into_response(),
    }
}
