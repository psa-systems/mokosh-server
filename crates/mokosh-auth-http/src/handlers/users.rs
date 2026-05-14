//! `/v1/auth/users` - admin-facing user management.
//!
//! Lists active/inactive users in the calling admin's tenant and lets
//! them suspend or reactivate accounts, change roles, force-delete,
//! resend the verification email, and trigger a password reset on the
//! user's behalf. All endpoints require an admin Bearer access token.
//! Tenant-scoped: cross-tenant probes via a forged user_id collapse to
//! 404 because every lookup re-checks the tenant_id matches the
//! admin's.
//!
//! Specified in docs/bunyip-settings/03-server-additions.md.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use mokosh_auth_core::{
    AuditEvent, AuthError, MfaChallengePurpose, NewPasswordResetToken, NewSignupToken, User,
    UserId, UserListFilter, UserRole, UserStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

// --- Token TTLs ---------------------------------------------------------
//
// Match the user-initiated flows so admin-initiated sends + retries
// behave identically downstream of the issue.
const SIGNUP_TOKEN_TTL_HOURS: i64 = 24;
const RESET_TOKEN_TTL_HOURS: i64 = 1;
const REASON_MAX_LEN: usize = 500;

// --- Response shapes ----------------------------------------------------

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
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Serialize)]
pub struct UserDetailResponse {
    pub user: UserView,
    pub available_role_transitions: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    /// "yes" | "no". Anything else (including absent) means no filter.
    #[serde(default)]
    pub mfa: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ChangeRoleBody {
    pub role: String,
    #[serde(default)]
    pub reason: Option<String>,
    /// Required iff the requested role is `admin` and the target is
    /// not already an admin (the "promote to admin" path).
    #[serde(default)]
    pub step_up_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteUserBody {
    pub reason: String,
    pub step_up_token: String,
}

// --- Helpers ------------------------------------------------------------

fn require_admin(user: &User) -> Result<(), HttpError> {
    if matches!(user.role, UserRole::Admin) {
        Ok(())
    } else {
        Err(HttpError(AuthError::Forbidden(
            "only admins may manage users".into(),
        )))
    }
}

fn parse_role(s: &str) -> Result<UserRole, HttpError> {
    UserRole::parse(s).ok_or_else(|| {
        HttpError(AuthError::InvalidRequest(format!(
            "unknown role '{s}'; expected one of admin/manager/finance/member/readonly"
        )))
    })
}

fn parse_status(s: &str) -> Result<UserStatus, HttpError> {
    UserStatus::parse(s).ok_or_else(|| {
        HttpError(AuthError::InvalidRequest(format!(
            "unknown status '{s}'; expected one of pending/active/suspended/deleted"
        )))
    })
}

/// Resolve the target user, enforce tenant scope, return 404 on miss.
/// Threaded into every per-user handler.
async fn resolve_target(
    st: &AuthHttpState,
    admin_tenant: mokosh_auth_core::TenantId,
    target_user_id: UserId,
) -> Result<User, HttpError> {
    st.provider
        .users
        .find_by_id(target_user_id)
        .await
        .map_err(HttpError)?
        .filter(|u| u.tenant_id == admin_tenant)
        .ok_or(HttpError(AuthError::NotFound))
}

/// Consume a step-up token that the supplied admin issued via
/// `/v1/auth/mfa/step-up/start`. Returns Ok on consume, Err with a
/// 403 envelope on miss / expiry / wrong-user.
async fn consume_step_up(
    st: &AuthHttpState,
    admin: &User,
    step_up_token: &str,
) -> Result<(), HttpError> {
    let token_hash = mokosh_auth_crypto::hash_opaque_token(step_up_token);
    let consumed = st
        .mfa_challenges
        .consume(token_hash, MfaChallengePurpose::StepUp)
        .await
        .map_err(|_| HttpError(AuthError::AccessDenied("step_up_invalid".into())))?;
    if consumed.user_id != admin.id {
        return Err(HttpError(AuthError::AccessDenied("step_up_invalid".into())));
    }
    Ok(())
}

/// Which roles a calling admin can transition the target into, given
/// the last-admin guard. Excludes the current role; the SPA disables
/// the dropdown for no-op transitions anyway.
async fn available_role_transitions(
    st: &AuthHttpState,
    target: &User,
) -> Result<Vec<&'static str>, HttpError> {
    let demoting_out_of_admin_would_brick = if matches!(target.role, UserRole::Admin) {
        let others = st
            .provider
            .users
            .count_active_admins_excluding(target.tenant_id, target.id)
            .await
            .map_err(HttpError)?;
        others == 0
    } else {
        false
    };

    let all: &[(UserRole, &'static str)] = &[
        (UserRole::Admin, "admin"),
        (UserRole::Manager, "manager"),
        (UserRole::Finance, "finance"),
        (UserRole::Member, "member"),
        (UserRole::ReadOnly, "readonly"),
    ];

    Ok(all
        .iter()
        .filter(|(r, _)| *r != target.role)
        .filter(|(r, _)| {
            // If demoting would brick the tenant, the ONLY legal
            // transition is staying admin (already excluded above);
            // hide every non-admin option from the dropdown so the
            // SPA doesn't even render a button that the server will
            // refuse.
            !(demoting_out_of_admin_would_brick && !matches!(r, UserRole::Admin))
        })
        .map(|(_, s)| *s)
        .collect())
}

// --- List ---------------------------------------------------------------

pub async fn list_users(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Query(q): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>, HttpError> {
    require_admin(&admin)?;

    let role = match q.role.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Some(parse_role(s)?),
        None => None,
    };
    let status = match q.status.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Some(parse_status(s)?),
        None => None,
    };
    let mfa_enrolled = match q.mfa.as_deref().map(str::trim) {
        Some("yes") | Some("true") | Some("1") => Some(true),
        Some("no") | Some("false") | Some("0") => Some(false),
        _ => None,
    };

    let filter = UserListFilter {
        search: q
            .search
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        role,
        status,
        mfa_enrolled,
        limit: q.limit.unwrap_or(50).clamp(1, 200),
        offset: q.offset.unwrap_or(0),
    };

    let (rows, total) = st
        .provider
        .users
        .list_filtered(admin.tenant_id, filter.clone())
        .await
        .map_err(HttpError)?;

    Ok(Json(UserListResponse {
        users: rows.into_iter().map(UserView::from).collect(),
        total,
        limit: filter.limit,
        offset: filter.offset,
    }))
}

// --- Get one ------------------------------------------------------------

pub async fn get_one(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Json<UserDetailResponse>, HttpError> {
    // Admin-or-manager visibility: Managers can VIEW user detail
    // pages (they need to look up an IC's email) but every mutation
    // endpoint independently requires Admin.
    if !matches!(admin.role, UserRole::Admin | UserRole::Manager) {
        return Err(HttpError(AuthError::Forbidden(
            "only admins or managers may view user detail".into(),
        )));
    }
    let target = resolve_target(&st, admin.tenant_id, UserId(user_id)).await?;
    let available = available_role_transitions(&st, &target).await?;
    Ok(Json(UserDetailResponse {
        user: target.into(),
        available_role_transitions: available,
    }))
}

// --- Suspend / reactivate (unchanged shape, last-admin guard cleaned up) -

async fn set_status(
    st: &AuthHttpState,
    admin: &User,
    user_id: UserId,
    new_status: UserStatus,
) -> Result<Response, HttpError> {
    require_admin(admin)?;
    let target = resolve_target(st, admin.tenant_id, user_id).await?;

    if matches!(new_status, UserStatus::Suspended) {
        if target.id == admin.id {
            return Err(HttpError(AuthError::InvalidRequest(
                "cannot suspend your own account".into(),
            )));
        }
        if matches!(target.role, UserRole::Admin) {
            let others = st
                .provider
                .users
                .count_active_admins_excluding(admin.tenant_id, target.id)
                .await
                .map_err(HttpError)?;
            if others == 0 {
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

// --- Change role --------------------------------------------------------

pub async fn change_role(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(user_id): Path<uuid::Uuid>,
    Json(body): Json<ChangeRoleBody>,
) -> Result<Response, HttpError> {
    require_admin(&admin)?;
    let reason = body.reason.unwrap_or_default();
    if reason.len() > REASON_MAX_LEN {
        return Err(HttpError(AuthError::InvalidRequest(format!(
            "reason: 0-{REASON_MAX_LEN} chars"
        ))));
    }

    let new_role = parse_role(&body.role)?;
    let target = resolve_target(&st, admin.tenant_id, UserId(user_id)).await?;

    // Self-guard: admins cannot change their own role.
    if target.id == admin.id {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "self_action_forbidden",
                       "message": "Cannot change your own role. Have another admin do it."})),
        )
            .into_response());
    }

    // No-op short-circuit. Skips both the audit row and the write.
    if target.role == new_role {
        return Ok((
            StatusCode::OK,
            Json(json!({"id": target.id.0.to_string(), "role": new_role.as_str(), "status": "no_change"})),
        )
            .into_response());
    }

    // Last-admin guard: demoting the only active admin in the tenant.
    let demoting_admin =
        matches!(target.role, UserRole::Admin) && !matches!(new_role, UserRole::Admin);
    if demoting_admin {
        let others = st
            .provider
            .users
            .count_active_admins_excluding(admin.tenant_id, target.id)
            .await
            .map_err(HttpError)?;
        if others == 0 {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "last_admin",
                    "message": "Cannot demote the only active admin. Promote another user to admin first."
                })),
            )
                .into_response());
        }
    }

    // Step-up guard: promotion to Admin requires the calling admin to
    // have just satisfied an MFA step-up challenge. Demotion / lateral
    // moves do not need step-up.
    let promoting_to_admin =
        matches!(new_role, UserRole::Admin) && !matches!(target.role, UserRole::Admin);
    if promoting_to_admin {
        match body.step_up_token.as_deref() {
            Some(t) if !t.is_empty() => consume_step_up(&st, &admin, t).await?,
            _ => {
                return Ok((
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "step_up_required",
                        "message": "Promoting a user to admin requires a step-up MFA challenge."
                    })),
                )
                    .into_response())
            }
        }
    }

    st.provider
        .users
        .set_role(target.id, new_role)
        .await
        .map_err(HttpError)?;

    let _ = st
        .provider
        .audit
        .record(
            Some(admin.tenant_id),
            Some(admin.id),
            None,
            AuditEvent::AdminAction {
                admin_id: admin.id,
                action: format!(
                    "user_role_changed:{}->{}",
                    target.role.as_str(),
                    new_role.as_str()
                ),
                target: target.id.0.to_string(),
            },
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(json!({"id": target.id.0.to_string(), "role": new_role.as_str()})),
    )
        .into_response())
}

// --- Delete -------------------------------------------------------------

pub async fn delete_user(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(user_id): Path<uuid::Uuid>,
    Json(body): Json<DeleteUserBody>,
) -> Result<Response, HttpError> {
    require_admin(&admin)?;
    let reason = body.reason.trim().to_string();
    if reason.is_empty() || reason.len() > REASON_MAX_LEN {
        return Err(HttpError(AuthError::InvalidRequest(format!(
            "reason: 1-{REASON_MAX_LEN} chars"
        ))));
    }

    let target = resolve_target(&st, admin.tenant_id, UserId(user_id)).await?;

    if target.id == admin.id {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "self_action_forbidden",
                       "message": "Cannot delete your own account."})),
        )
            .into_response());
    }

    if matches!(target.status, UserStatus::Deleted) {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "already_deleted"})),
        )
            .into_response());
    }

    // Last-admin guard.
    if matches!(target.role, UserRole::Admin) {
        let others = st
            .provider
            .users
            .count_active_admins_excluding(admin.tenant_id, target.id)
            .await
            .map_err(HttpError)?;
        if others == 0 {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "last_admin",
                    "message": "Cannot delete the only active admin. Promote another user first."
                })),
            )
                .into_response());
        }
    }

    // Step-up is mandatory for delete.
    if body.step_up_token.is_empty() {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "step_up_required",
                "message": "Deleting a user requires a step-up MFA challenge."
            })),
        )
            .into_response());
    }
    consume_step_up(&st, &admin, &body.step_up_token).await?;

    // Mark deleted, free the email, revoke sessions. The email rewrite
    // uses the user's id as a stable suffix so two deleted-then-re-
    // created accounts for the same address don't collide.
    let freed_email = format!("deleted-{}+{}", target.id.0, target.email);
    let original_email = target.email.clone();
    st.provider
        .users
        .set_status(target.id, UserStatus::Deleted)
        .await
        .map_err(HttpError)?;
    if let Err(e) = st
        .provider
        .users
        .update_email(target.id, &freed_email)
        .await
    {
        // Best-effort: status flip already committed; log + continue.
        tracing::warn!(target=%target.id.0, error=?e, "user.delete: failed to free email");
    }
    let _ = st.provider.sessions.revoke_all_for_user(target.id).await;

    let _ = st
        .provider
        .audit
        .record(
            Some(admin.tenant_id),
            Some(admin.id),
            None,
            AuditEvent::AdminAction {
                admin_id: admin.id,
                action: format!("user_deleted:{}:{}", original_email, reason),
                target: target.id.0.to_string(),
            },
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(json!({"id": target.id.0.to_string(), "status": "deleted"})),
    )
        .into_response())
}

// --- Resend verify ------------------------------------------------------

pub async fn resend_verify(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Response, HttpError> {
    require_admin(&admin)?;
    let target = resolve_target(&st, admin.tenant_id, UserId(user_id)).await?;

    if target.email_verified_at.is_some() {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "already_verified",
                       "message": "Email is already verified."})),
        )
            .into_response());
    }
    if !matches!(target.status, UserStatus::Pending) {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "not_pending",
                       "message": "Resend verification only applies to pending accounts."})),
        )
            .into_response());
    }

    let now = Utc::now();
    // Coalesce repeat sends within the existing 24h dedup window.
    if st
        .signup_tokens
        .find_open_by_email(&target.email, now)
        .await?
        .is_some()
    {
        return Ok((StatusCode::OK, Json(json!({"status": "already_sent"}))).into_response());
    }

    let raw_token = mokosh_auth_crypto::generate_opaque_token();
    let token_hash = mokosh_auth_crypto::hash_opaque_token(&raw_token);
    st.signup_tokens
        .issue(NewSignupToken {
            email: target.email.clone(),
            token_hash,
            expires_at: now + Duration::hours(SIGNUP_TOKEN_TTL_HOURS),
        })
        .await?;

    if let Err(e) = st.mailer.send_signup(&target.email, &raw_token).await {
        tracing::error!(email=%target.email, "resend-verify email send failed: {e}");
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
                action: format!("user_resend_verify:{}", target.email),
                target: target.id.0.to_string(),
            },
        )
        .await;

    Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response())
}

// --- Admin-triggered password reset -------------------------------------

pub async fn admin_trigger_password_reset(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Response, HttpError> {
    require_admin(&admin)?;
    let target = resolve_target(&st, admin.tenant_id, UserId(user_id)).await?;

    if matches!(target.status, UserStatus::Deleted) {
        return Err(HttpError(AuthError::NotFound));
    }
    if target.email_verified_at.is_none() {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "email_not_verified",
                "message": "Trigger 'Resend verification' first."
            })),
        )
            .into_response());
    }

    let now = Utc::now();
    if st
        .password_reset_tokens
        .find_open_by_email(&target.email, now)
        .await?
        .is_some()
    {
        return Ok((StatusCode::OK, Json(json!({"status": "already_sent"}))).into_response());
    }

    let raw_token = mokosh_auth_crypto::generate_opaque_token();
    let token_hash = mokosh_auth_crypto::hash_opaque_token(&raw_token);
    st.password_reset_tokens
        .issue(NewPasswordResetToken {
            email: target.email.clone(),
            token_hash,
            expires_at: now + Duration::hours(RESET_TOKEN_TTL_HOURS),
        })
        .await?;

    if let Err(e) = st
        .mailer
        .send_password_reset(&target.email, &raw_token)
        .await
    {
        tracing::error!(email=%target.email, "admin-triggered password-reset send failed: {e}");
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
                action: format!("user_password_reset_triggered:{}", target.email),
                target: target.id.0.to_string(),
            },
        )
        .await;

    Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response())
}
