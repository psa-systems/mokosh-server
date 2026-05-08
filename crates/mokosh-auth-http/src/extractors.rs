//! Axum extractors for the OP's own routes.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use mokosh_auth_core::{AuthError, OpSession, User, UserId, UserStatus};
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
            .ok_or_else(|| HttpError(mokosh_auth_core::AuthError::LoginRequired))?;
        let session = st
            .provider
            .sessions
            .find_by_sid(&sid)
            .await
            .map_err(HttpError)?
            .ok_or_else(|| HttpError(mokosh_auth_core::AuthError::LoginRequired))?;
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
            .ok_or_else(|| HttpError(mokosh_auth_core::AuthError::LoginRequired))?;
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
            .ok_or_else(|| HttpError(AuthError::LoginRequired))?
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

        let user_id = data
            .claims
            .sub
            .parse::<uuid::Uuid>()
            .map_err(|_| HttpError(AuthError::AccessDenied("malformed sub".into())))?;
        let user = st
            .provider
            .users
            .find_by_id(UserId(user_id))
            .await
            .map_err(HttpError)?
            .ok_or_else(|| HttpError(AuthError::AccessDenied("user not found".into())))?;
        if !matches!(user.status, UserStatus::Active) {
            return Err(HttpError(AuthError::Forbidden("user not active".into())));
        }
        Ok(BearerUser(user))
    }
}

#[derive(Debug, Deserialize)]
struct BearerClaims {
    sub: String,
}
