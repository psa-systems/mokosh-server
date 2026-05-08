//! `/v1/auth/users` - admin-facing user management.
//!
//! Lists active/inactive users in the calling admin's tenant and lets
//! them suspend or reactivate accounts. All endpoints require an
//! admin Bearer access token. Tenant-scoped: cross-tenant probes via
//! a forged user_id collapse to 404 because every lookup re-checks
//! the tenant_id matches the admin's.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{AuditEvent, AuthError, User, UserId, UserRole, UserStatus};
use serde::Serialize;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    pub email_verified: bool,
    pub mfa_enrolled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserView {
    fn from(u: User) -> Self {
        Self {
            id: u.id.0.to_string(),
            email: u.email,
            role: u.role.as_str().to_string(),
            status: u.status.as_str().to_string(),
            first_name: u.first_name,
            last_name: u.last_name,
            email_verified: u.email_verified_at.is_some(),
            mfa_enrolled: u.mfa_enrolled,
            last_login_at: u.last_login_at,
            created_at: u.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub users: Vec<UserView>,
}

fn require_admin(user: &User) -> Result<(), HttpError> {
    if matches!(user.role, UserRole::Admin) {
        Ok(())
    } else {
        Err(HttpError(AuthError::Forbidden(
            "only admins may manage users".into(),
        )))
    }
}

pub async fn list_users(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
) -> Result<Json<UserListResponse>, HttpError> {
    require_admin(&admin)?;
    let users = st
        .provider
        .users
        .list_by_tenant(admin.tenant_id)
        .await
        .map_err(HttpError)?;
    Ok(Json(UserListResponse {
        users: users.into_iter().map(UserView::from).collect(),
    }))
}

async fn set_status(
    st: &AuthHttpState,
    admin: &User,
    user_id: UserId,
    new_status: UserStatus,
) -> Result<Response, HttpError> {
    require_admin(admin)?;
    // Tenant-scope check: cross-tenant 404 to avoid id enumeration.
    let target = st
        .provider
        .users
        .find_by_id(user_id)
        .await
        .map_err(HttpError)?
        .filter(|u| u.tenant_id == admin.tenant_id)
        .ok_or(HttpError(AuthError::NotFound))?;
    // Two limbo guards on suspension:
    //
    //   1. An admin cannot suspend themselves. Even with other
    //      admins around the UX trap of clicking your own Suspend
    //      and immediately losing access is worth catching at the
    //      API layer.
    //   2. The LAST active admin in a tenant cannot be suspended,
    //      regardless of who is doing the suspending. Without this,
    //      a tenant could end up with zero administrators and no
    //      recovery path short of a server-side intervention.
    //
    // The check counts active admins INCLUDING the target, then
    // refuses if the target is an admin and removing them would
    // drop the count to zero.
    if matches!(new_status, UserStatus::Suspended) {
        if target.id == admin.id {
            return Err(HttpError(AuthError::InvalidRequest(
                "cannot suspend your own account".into(),
            )));
        }
        if matches!(target.role, UserRole::Admin) {
            let active_admins = st
                .provider
                .users
                .list_by_tenant(admin.tenant_id)
                .await
                .map_err(HttpError)?
                .into_iter()
                .filter(|u| {
                    matches!(u.role, UserRole::Admin) && matches!(u.status, UserStatus::Active)
                })
                .count();
            if active_admins <= 1 {
                return Err(HttpError(AuthError::InvalidRequest(
                    "cannot suspend the last active admin in the tenant".into(),
                )));
            }
        }
    }

    st.provider
        .users
        .set_status(user_id, new_status)
        .await
        .map_err(HttpError)?;

    // Suspending an account also revokes every active OP session for
    // that user, otherwise they keep the existing access token until
    // it expires. Activation does NOT auto-revoke; the user simply
    // becomes able to authenticate again.
    if matches!(new_status, UserStatus::Suspended) {
        let _ = st.provider.sessions.revoke_all_for_user(user_id).await;
    }

    let _ = st
        .provider
        .audit
        .record(
            Some(admin.tenant_id),
            Some(admin.id),
            None,
            AuditEvent::AdminAction {
                admin_id: admin.id,
                action: format!("user_set_status:{}", new_status.as_str()),
                target: user_id.0.to_string(),
            },
        )
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn suspend_user(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Response, HttpError> {
    set_status(&st, &admin, UserId(user_id), UserStatus::Suspended).await
}

pub async fn reactivate_user(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Response, HttpError> {
    set_status(&st, &admin, UserId(user_id), UserStatus::Active).await
}
