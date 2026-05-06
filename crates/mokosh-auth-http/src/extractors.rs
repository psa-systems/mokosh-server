//! Axum extractors for the OP's own routes.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::cookie::CookieJar;
use mokosh_auth_core::{OpSession, User, UserStatus};
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
