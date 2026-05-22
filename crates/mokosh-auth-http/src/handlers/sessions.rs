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
use mokosh_auth_core::{AuthError, OpSessionId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::{BearerSessionId, BearerUser};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// `true` when this row is the OP session the caller is signed
    /// in under right now. Sourced from the `mokosh_op_session_id`
    /// claim on the access token used to make this request. The SPA
    /// renders a "Current session" badge on this row.
    pub is_current: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionView>,
}

pub async fn list_my_sessions(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
    BearerSessionId(current_sid): BearerSessionId,
) -> Result<Json<SessionListResponse>, HttpError> {
    let now = st.provider.clock.now();
    let sessions = st
        .provider
        .sessions
        .list_active_for_user(user.id, now)
        .await
        .map_err(HttpError)?;
    let views: Vec<SessionView> = sessions
        .into_iter()
        .map(|s| SessionView {
            is_current: current_sid.map(|c| c == s.id).unwrap_or(false),
            id: s.id.0.to_string(),
            created_at: s.created_at,
            last_active_at: s.last_active_at,
            expires_at: s.expires_at,
            user_agent: s.user_agent,
            ip: s.ip.map(|i| i.to_string()),
            display_name: s.display_name,
        })
        .collect();
    Ok(Json(SessionListResponse { sessions: views }))
}

/// `GET /v1/auth/users/:user_id/sessions`
///
/// Admin-scoped variant of `list_my_sessions`. Returns the target
/// user's active sessions. Tenant-scoped: the caller must have an
/// Admin membership in the same tenant as the target user (via
/// memberships.find), otherwise 404. Used by the user-detail page's
/// Sessions section.
pub async fn list_user_sessions_admin(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(target_id): Path<uuid::Uuid>,
) -> Result<Json<SessionListResponse>, HttpError> {
    use mokosh_auth_core::UserRole;
    if !matches!(admin.role, UserRole::Admin) {
        return Err(HttpError(AuthError::Forbidden("admin required".into())));
    }
    // 404 unless the target has an active membership in the admin's tenant.
    let m = st
        .memberships
        .find(mokosh_auth_core::UserId(target_id), admin.tenant_id)
        .await
        .map_err(HttpError)?
        .ok_or(HttpError(AuthError::NotFound))?;
    let _ = m; // membership existence is the gate; we don't read fields off it.

    let now = st.provider.clock.now();
    let sessions = st
        .provider
        .sessions
        .list_active_for_user(mokosh_auth_core::UserId(target_id), now)
        .await
        .map_err(HttpError)?;
    let views: Vec<SessionView> = sessions
        .into_iter()
        .map(|s| SessionView {
            is_current: false, // admin viewing another user's sessions
            id: s.id.0.to_string(),
            created_at: s.created_at,
            last_active_at: s.last_active_at,
            expires_at: s.expires_at,
            user_agent: s.user_agent,
            ip: s.ip.map(|i| i.to_string()),
            display_name: s.display_name,
        })
        .collect();
    Ok(Json(SessionListResponse { sessions: views }))
}

/// `POST /v1/auth/users/:user_id/sessions/:session_id/revoke`
///
/// Admin-scoped: force-revoke one of another user's sessions. Same
/// tenant gating as the list endpoint. Also revokes any refresh
/// families bound to the session, mirroring `revoke_my_session`.
pub async fn revoke_user_session_admin(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path((target_id, session_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Response, HttpError> {
    use mokosh_auth_core::{AuditEvent, UserRole};
    if !matches!(admin.role, UserRole::Admin) {
        return Err(HttpError(AuthError::Forbidden("admin required".into())));
    }
    // Tenant gate.
    let _ = st
        .memberships
        .find(mokosh_auth_core::UserId(target_id), admin.tenant_id)
        .await
        .map_err(HttpError)?
        .ok_or(HttpError(AuthError::NotFound))?;

    let sid = OpSessionId(session_id);
    let session = st
        .provider
        .sessions
        .find_by_id(sid)
        .await
        .map_err(HttpError)?;
    // Confirm the session belongs to the claimed target. 404 otherwise -
    // prevents using this as a cross-user session-id enumeration oracle.
    let owns = matches!(&session, Some(s) if s.user_id == mokosh_auth_core::UserId(target_id));
    if !owns {
        return Err(HttpError(AuthError::NotFound));
    }

    let now = st.provider.clock.now();
    st.provider
        .sessions
        .revoke(sid, now)
        .await
        .map_err(HttpError)?;
    let _ = st
        .provider
        .refresh
        .revoke_families_for_session(sid, "admin_revoked_session", now)
        .await;

    let _ = st
        .provider
        .audit
        .record(
            Some(admin.tenant_id),
            Some(admin.id),
            None,
            AuditEvent::AdminAction {
                admin_id: admin.id,
                action: "user_session_revoked".into(),
                target: format!("{}/{}", target_id, session_id),
            },
        )
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /v1/auth/sessions/revoke-others`
///
/// Revoke every active op_session for the caller EXCEPT the current
/// one (identified by the `sid` claim on the calling Bearer token).
/// Used by the "Sign out of all other sessions" affordance on
/// `/settings/sessions`. Doc 06 polish item #2.
pub async fn revoke_others(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
    BearerSessionId(current_sid): BearerSessionId,
) -> Result<Response, HttpError> {
    let now = st.provider.clock.now();
    let actives = st
        .provider
        .sessions
        .list_active_for_user(user.id, now)
        .await
        .map_err(HttpError)?;
    for s in actives {
        if Some(s.id) == current_sid {
            continue;
        }
        let _ = st.provider.sessions.revoke(s.id, now).await;
        let _ = st
            .provider
            .refresh
            .revoke_families_for_session(s.id, "user_revoked_others", now)
            .await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
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

#[derive(Debug, Deserialize)]
pub struct RenameBody {
    #[serde(default)]
    pub display_name: Option<String>,
}

/// `POST /v1/auth/sessions/{session_id}/rename`
///
/// Set or clear the user-supplied label on a session. Empty / null /
/// whitespace-only collapses to NULL. Ownership-checked; foreign
/// session ids return 404 so this can't be used as an enumeration
/// oracle.
pub async fn rename_my_session(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
    Path(session_id): Path<uuid::Uuid>,
    Json(body): Json<RenameBody>,
) -> Result<Response, HttpError> {
    let id = OpSessionId(session_id);
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
    if let Some(name) = body.display_name.as_deref() {
        if name.len() > 100 {
            return Err(HttpError(AuthError::InvalidRequest(
                "display_name <=100 chars".into(),
            )));
        }
    }
    st.provider
        .sessions
        .rename(id, user.id, body.display_name.as_deref())
        .await
        .map_err(HttpError)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
