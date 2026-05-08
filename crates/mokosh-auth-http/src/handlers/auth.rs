//! `/v1/auth/*` handlers: login, logout, first-run setup.
//!
//! `/v1/auth/login` is the SPA's primary credential entry point. It does
//! two things in one round-trip:
//!   1. authenticates email + password and creates an OP session (the
//!      `sid` cookie); same as before.
//!   2. when the request includes `client_id`, also mints OIDC tokens
//!      for that client (RFC 9068 access token + ID token + refresh
//!      family) and returns them in the response body.
//!
//! Step (2) lets first-party SPAs (the Mokosh hub UI) skip the OIDC
//! authorize-redirect-callback dance, which would otherwise force users
//! through a separate OP login page that renders the same form. The
//! tokens are minted with the same code path the OIDC token endpoint
//! uses for `authorization_code`, so audiences, scopes, signatures, and
//! refresh-rotation behaviour are identical to the federated flow.

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use mokosh_auth_core::{
    AuditEvent, AuthError, ClientId, NewRefreshToken, NewRefreshTokenFamily, RefreshTokenId,
};
use mokosh_auth_crypto::{generate_opaque_token, hash_opaque_token};
use mokosh_auth_oidc::tokens::{mint_access_token, mint_id_token};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cookies::{clear_op_session_cookie, set_op_session_cookie};
use crate::errors::HttpError;
use crate::extractors::CurrentOpSession;
use crate::router::AuthHttpState;

/// Default scopes minted for first-party SPA logins when the client
/// omits an explicit `scope` field. `openid` is required for an ID
/// token; `email` populates the email/email_verified ID-token claims;
/// `offline_access` opts the SPA into receiving a refresh token.
const DEFAULT_FIRST_PARTY_SCOPE: &[&str] = &["openid", "email", "offline_access"];

/// Request body for `/v1/auth/login`. The local-auth fields
/// (email, password, optional tenant pin) come from
/// [`crate::local_auth::LocalLoginRequest`]; the OIDC fields are
/// optional and only consulted when the caller wants tokens minted
/// in the same call.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    #[serde(default)]
    pub tenant_id: Option<uuid::Uuid>,
    pub email: String,
    pub password: String,
    /// First-party SPA client UUID. When present the response includes a
    /// minted token bundle for this client; when absent only the OP
    /// session cookie is set (legacy behaviour). The client must allow
    /// the `authorization_code` grant; we treat the local-password
    /// authentication step as the equivalent of a code exchange.
    #[serde(default)]
    pub client_id: Option<uuid::Uuid>,
    /// Optional space-separated scope list. Defaults to
    /// `openid email offline_access`.
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub tenant_id: String,
    /// Present when the request supplied `client_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenBundle>,
}

#[derive(Debug, Serialize)]
pub struct TokenBundle {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub id_token: String,
    pub refresh_token: String,
    pub scope: String,
}

pub async fn login(
    State(st): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
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
    let local_req = crate::local_auth::LocalLoginRequest {
        tenant_id: req.tenant_id,
        email: req.email.clone(),
        password: req.password.clone(),
    };
    let ok = st.local_auth.login(local_req, ip, ua).await?;

    let tokens = if let Some(cid) = req.client_id {
        Some(mint_first_party_tokens(&st, &ok, cid, req.scope.as_deref()).await?)
    } else {
        None
    };

    let cookie = set_op_session_cookie(
        &st.cookie_cfg,
        ok.session.sid.clone(),
        st.provider.cfg.op_session_ttl,
    );
    let body = LoginResponse {
        user_id: ok.session.user_id.0.to_string(),
        tenant_id: ok.session.tenant_id.0.to_string(),
        tokens,
    };
    Ok((jar.add(cookie), Json(body)).into_response())
}

async fn mint_first_party_tokens(
    st: &AuthHttpState,
    ok: &crate::local_auth::LocalLoginOk,
    client_id: uuid::Uuid,
    scope_param: Option<&str>,
) -> Result<TokenBundle, AuthError> {
    let provider = &st.provider;
    let client = provider
        .clients
        .find_by_client_id(ClientId(client_id))
        .await?
        .ok_or(AuthError::InvalidClient)?;
    if !client
        .allowed_grant_types
        .contains(&mokosh_auth_core::GrantType::AuthorizationCode)
    {
        return Err(AuthError::UnauthorizedClient(
            "client cannot receive first-party login tokens".into(),
        ));
    }
    let scope_vec: Vec<String> = scope_param
        .map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>())
        .filter(|v: &Vec<_>| !v.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_FIRST_PARTY_SCOPE
                .iter()
                .map(|&s| s.to_string())
                .collect()
        });

    let now = provider.clock.now();
    let acr = "urn:mokosh:loa:pwd";
    let amr: Vec<String> = vec!["pwd".to_string()];

    let access = mint_access_token(
        &provider.keys,
        &provider.cfg,
        &ok.user,
        &client,
        &scope_vec,
        ok.session.created_at,
        acr,
        &amr,
        now,
    )?;
    let id_token = mint_id_token(
        &provider.keys,
        &provider.cfg,
        &ok.user,
        &client,
        &scope_vec,
        ok.session.created_at,
        acr,
        &amr,
        None,
        &access.token,
        now,
    )?;

    let raw_refresh = generate_opaque_token();
    let refresh_hash = hash_opaque_token(&raw_refresh);
    let new_token = NewRefreshToken {
        id: RefreshTokenId::new(),
        token_hash: refresh_hash,
        scope: scope_vec.clone(),
        idle_expires_at: now + client.refresh_idle_ttl,
        absolute_expires_at: now + client.refresh_token_ttl,
        ip: ok.session.ip,
        user_agent: ok.session.user_agent.clone(),
    };
    let family = NewRefreshTokenFamily {
        client_id: client.client_id,
        user_id: ok.user.id,
        tenant_id: ok.user.tenant_id,
        op_session_id: Some(ok.session.id),
    };
    provider.refresh.issue_initial(family, new_token).await?;

    let _ = provider
        .audit
        .record(
            Some(ok.user.tenant_id),
            Some(ok.user.id),
            None,
            AuditEvent::TokenIssued {
                user_id: ok.user.id,
                client_id: client.client_id,
                scope: scope_vec.clone(),
                jti: access.jti.clone(),
            },
        )
        .await;

    Ok(TokenBundle {
        access_token: access.token,
        token_type: "Bearer",
        expires_in: (access.expires_at - now).num_seconds().max(0),
        id_token,
        refresh_token: raw_refresh,
        scope: scope_vec.join(" "),
    })
}

pub async fn logout(
    State(st): State<Arc<AuthHttpState>>,
    jar: CookieJar,
    session: Result<CurrentOpSession, HttpError>,
) -> Response {
    if let Ok(CurrentOpSession(s)) = session {
        let now = st.provider.clock.now();
        let _ = st.provider.sessions.revoke(s.id, now).await;
        // Mirror of the /oauth2/revoke path: revoking the session
        // must also kill every refresh-token family that was issued
        // from it, otherwise stale refresh tokens would survive a
        // logout and could mint fresh access tokens until their
        // own absolute TTL.
        let _ = st
            .provider
            .refresh
            .revoke_families_for_session(s.id, "logout", now)
            .await;
    }
    let cleared = jar.remove(clear_op_session_cookie(&st.cookie_cfg));
    (cleared, StatusCode::NO_CONTENT).into_response()
}
