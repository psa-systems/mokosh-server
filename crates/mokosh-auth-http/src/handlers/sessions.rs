//! `/v1/auth/sessions` - self-service session management for the
//! signed-in user. Lists every active OP session this user has open
//! and lets them revoke any of them ("log out other devices").
//!
//! Authentication is Bearer at+jwt (cross-origin friendly), not cookie:
//! the SPA hits this endpoint over CORS where credentials are not
//! sent.
//!
//! Revoking a session also revokes every refresh-token family that
//! was issued from it, so the device whose session got killed cannot
//! mint a fresh access token from the refresh it still holds.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{AuthError, OpSession, OpSessionId};
use serde::Serialize;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

#[derive(Debug, Serialize)]
pub struct SessionView {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

impl From<OpSession> for SessionView {
    fn from(s: OpSession) -> Self {
        Self {
            id: s.id.0.to_string(),
            created_at: s.created_at,
            last_active_at: s.last_active_at,
            expires_at: s.expires_at,
            user_agent: s.user_agent,
            ip: s.ip.map(|i| i.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionView>,
}

pub async fn list_my_sessions(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
) -> Result<Json<SessionListResponse>, HttpError> {
    let now = st.provider.clock.now();
    let sessions = st
        .provider
        .sessions
        .list_active_for_user(user.id, now)
        .await
        .map_err(HttpError)?;
    Ok(Json(SessionListResponse {
        sessions: sessions.into_iter().map(SessionView::from).collect(),
    }))
}

pub async fn revoke_my_session(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
    Path(session_id): Path<uuid::Uuid>,
) -> Result<Response, HttpError> {
    let id = OpSessionId(session_id);
    let now = st.provider.clock.now();

    // Ownership check: the caller may only revoke sessions belonging
    // to themselves. We surface a 404 (rather than 403) so this
    // endpoint cannot be used to enumerate session ids of other
    // users.
    let session = st
        .provider
        .sessions
        .find_by_id(id)
        .await
        .map_err(HttpError)?;
    let owns = matches!(&session, Some(s) if s.user_id == user.id);
    if !owns {
        return Err(HttpError(AuthError::NotFound));
    }

    st.provider
        .sessions
        .revoke(id, now)
        .await
        .map_err(HttpError)?;
    // Mirror of /oauth2/revoke behaviour: revoking the session must
    // also kill the refresh families issued from it.
    let _ = st
        .provider
        .refresh
        .revoke_families_for_session(id, "user_revoked_session", now)
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}
