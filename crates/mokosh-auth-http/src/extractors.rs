//! Axum extractors for the OP's own routes.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use mokosh_auth_core::{AuthError, OpSession, OpSessionId, User, UserId, UserStatus};
use serde::Deserialize;
use std::sync::Arc;

use crate::cookies::OP_SESSION_COOKIE;
use crate::errors::HttpError;
use crate::router::AuthHttpState;

/// A valid (unrevoked, unexpired) OP session resolved from the
/// `mokosh_op_session` cookie. Use this when the route only needs the
/// session, not the user record.
#[derive(Debug, Clone)]
pub struct CurrentOpSession(pub OpSession);

impl<S> FromRequestParts<S> for CurrentOpSession
where
    S: Send + Sync,
    Arc<AuthHttpState>: axum::extract::FromRef<S>,
{
    type Rejection = HttpError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let st: Arc<AuthHttpState> = axum::extract::FromRef::from_ref(state);
        let jar = CookieJar::from_headers(&parts.headers);
        let sid = jar
            .get(OP_SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .ok_or(HttpError(mokosh_auth_core::AuthError::LoginRequired))?;
        let session = st
            .provider
            .sessions
            .find_by_sid(&sid)
            .await
            .map_err(HttpError)?
            .ok_or(HttpError(mokosh_auth_core::AuthError::LoginRequired))?;
        if !session.is_active(st.provider.clock.now()) {
            return Err(HttpError(mokosh_auth_core::AuthError::LoginRequired));
        }
        Ok(CurrentOpSession(session))
    }
}

/// The `User` belonging to the current OP session, additionally checked
/// to be active.
#[derive(Debug, Clone)]
pub struct CurrentUser(pub User);

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
    Arc<AuthHttpState>: axum::extract::FromRef<S>,
{
    type Rejection = HttpError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let st: Arc<AuthHttpState> = axum::extract::FromRef::from_ref(state);
        let session = CurrentOpSession::from_request_parts(parts, state).await?.0;
        let user = st
            .provider
            .users
            .find_by_id(session.user_id)
            .await
            .map_err(HttpError)?
            .ok_or(HttpError(mokosh_auth_core::AuthError::LoginRequired))?;
        if !matches!(user.status, UserStatus::Active) {
            return Err(HttpError(mokosh_auth_core::AuthError::Forbidden(
                "user not active".into(),
            )));
        }
        Ok(CurrentUser(user))
    }
}

/// Active `User` resolved from a Bearer at+jwt access token (RFC 9068).
///
/// Use this on routes that the SPA needs to call cross-origin (where
/// the OP-session cookie is not available because CORS does not allow
/// credentials). Verification is in-process against the same
/// `OidcKeySet` the issuer endpoint uses, so there is no JWKS fetch.
#[derive(Debug, Clone)]
pub struct BearerUser(pub User);

/// Optional OP-session id parsed from the same Bearer access token
/// the `BearerUser` extractor used. Returned alongside `BearerUser`
/// when a route needs to identify the "current session" for the UI
/// (e.g. the active-sessions list marks one row as "current"). The
/// claim is omitted on refresh-grant tokens, so this is `Option`.
#[derive(Debug, Clone)]
pub struct BearerSessionId(pub Option<OpSessionId>);

impl<S> FromRequestParts<S> for BearerSessionId
where
    S: Send + Sync,
    Arc<AuthHttpState>: axum::extract::FromRef<S>,
{
    type Rejection = HttpError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let st: Arc<AuthHttpState> = axum::extract::FromRef::from_ref(state);

        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                parts
                    .headers
                    .get(header::AUTHORIZATION)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.strip_prefix("bearer "))
            })
            .ok_or(HttpError(AuthError::LoginRequired))?
            .trim();

        let header_data = decode_header(token)
            .map_err(|_| HttpError(AuthError::AccessDenied("malformed token".into())))?;
        let kid = header_data
            .kid
            .ok_or_else(|| HttpError(AuthError::AccessDenied("missing kid".into())))?;
        let dk = st
            .provider
            .keys
            .decoding_key(&kid)
            .ok_or_else(|| HttpError(AuthError::AccessDenied("unknown kid".into())))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[st.provider.cfg.issuer_str().trim_end_matches('/')]);
        validation.leeway = 30;
        validation.validate_aud = false;

        #[derive(Deserialize)]
        struct C {
            #[serde(default)]
            mokosh_op_session_id: Option<String>,
        }
        let data = decode::<C>(token, dk, &validation)
            .map_err(|_| HttpError(AuthError::AccessDenied("invalid token".into())))?;
        let session_id = data
            .claims
            .mokosh_op_session_id
            .as_deref()
            .and_then(|s| s.parse::<uuid::Uuid>().ok())
            .map(OpSessionId);
        Ok(BearerSessionId(session_id))
    }
}

impl<S> FromRequestParts<S> for BearerUser
where
    S: Send + Sync,
    Arc<AuthHttpState>: axum::extract::FromRef<S>,
{
    type Rejection = HttpError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let st: Arc<AuthHttpState> = axum::extract::FromRef::from_ref(state);

        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                parts
                    .headers
                    .get(header::AUTHORIZATION)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.strip_prefix("bearer "))
            })
            .ok_or(HttpError(AuthError::LoginRequired))?
            .trim();

        let header_data = decode_header(token)
            .map_err(|_| HttpError(AuthError::AccessDenied("malformed token".into())))?;
        // RFC 9068: typ MUST be "at+jwt". Reject anything else - id
        // tokens and refresh tokens are not valid here.
        if header_data.typ.as_deref() != Some("at+jwt") {
            return Err(HttpError(AuthError::AccessDenied(
                "wrong token type".into(),
            )));
        }
        let kid = header_data
            .kid
            .ok_or_else(|| HttpError(AuthError::AccessDenied("missing kid".into())))?;
        let dk = st
            .provider
            .keys
            .decoding_key(&kid)
            .ok_or_else(|| HttpError(AuthError::AccessDenied("unknown kid".into())))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[st.provider.cfg.issuer_str().trim_end_matches('/')]);
        validation.leeway = 30;
        // Audience is per-client; we don't gate at this layer.
        validation.validate_aud = false;

        let data = decode::<BearerClaims>(token, dk, &validation)
            .map_err(|_| HttpError(AuthError::AccessDenied("invalid token".into())))?;

        // Op-session revocation check. The access token carries
        // `mokosh_op_session_id`; we look up the op_sessions row and
        // reject the token if the row is missing, revoked, or expired.
        // Without this, an access token stays valid until its `exp`
        // even after /v1/auth/logout revoked the originating session,
        // which means a Bunyip sign-out doesn't immediately propagate
        // to RP-side calls that talk back to mokosh (mokosh-clients's
        // `/v1/auth/me`, etc.).
        if let Some(sid_str) = data.claims.mokosh_op_session_id.as_deref() {
            if let Ok(sid) = sid_str.parse::<uuid::Uuid>() {
                let row = st
                    .provider
                    .sessions
                    .find_by_id(mokosh_auth_core::OpSessionId(sid))
                    .await
                    .map_err(HttpError)?;
                match row {
                    Some(s) if s.is_active(st.provider.clock.now()) => { /* ok */ }
                    Some(_) => {
                        return Err(HttpError(AuthError::AccessDenied(
                            "op session revoked".into(),
                        )));
                    }
                    None => {
                        return Err(HttpError(AuthError::AccessDenied(
                            "op session not found".into(),
                        )));
                    }
                }
            }
        }

        let user_id = data
            .claims
            .sub
            .parse::<uuid::Uuid>()
            .map_err(|_| HttpError(AuthError::AccessDenied("malformed sub".into())))?;
        let mut user = st
            .provider
            .users
            .find_by_id(UserId(user_id))
            .await
            .map_err(HttpError)?
            .ok_or_else(|| HttpError(AuthError::AccessDenied("user not found".into())))?;
        if !matches!(user.status, UserStatus::Active) {
            return Err(HttpError(AuthError::Forbidden("user not active".into())));
        }

        // Resolve role through the active tenant's membership rather
        // than the user's home-tenant default. The JWT carries
        // `mokosh_active_tenant`; we look up `memberships.role` for
        // that (user, tenant) pair and use it as the effective role
        // for this request. Without this, a user whose home-tenant
        // role is Admin keeps Admin everywhere they switch into,
        // bypassing the per-tenant role taxonomy.
        //
        // `users.role` is left in place on the User struct as the
        // home-tenant default for cases where no active_tenant claim
        // is present (legacy tokens) or no membership exists (e.g.
        // tenant was just deleted under us; the user gets a 403).
        if let Some(active) = data
            .claims
            .mokosh_active_tenant
            .as_deref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .map(mokosh_auth_core::TenantId)
        {
            let m = st
                .memberships
                .find(user.id, active)
                .await
                .map_err(HttpError)?
                .ok_or_else(|| {
                    HttpError(AuthError::Forbidden(
                        "no membership in active tenant".into(),
                    ))
                })?;
            if !matches!(m.status, mokosh_auth_core::MembershipStatus::Active) {
                return Err(HttpError(AuthError::Forbidden(
                    "membership in active tenant is suspended".into(),
                )));
            }
            user.role = m.role;
            user.tenant_id = m.tenant_id;
        }
        Ok(BearerUser(user))
    }
}

#[derive(Debug, Deserialize)]
struct BearerClaims {
    sub: String,
    #[serde(default)]
    mokosh_active_tenant: Option<String>,
    #[serde(default)]
    mokosh_op_session_id: Option<String>,
}
