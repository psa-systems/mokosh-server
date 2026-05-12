//! `/v1/auth/me/*` - self-service profile + password endpoints.
//!
//! All BearerUser-gated. Today the surface is:
//!   - GET  /v1/auth/me                 returns the caller's profile
//!   - PUT  /v1/auth/me/profile         updates first/last name, timezone, avatar
//!   - POST /v1/auth/me/password        change password while signed in

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use mokosh_auth_core::{AuditEvent, AuthError};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

#[derive(Debug, Serialize)]
pub struct MeView {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub timezone: String,
    pub locale: String,
    pub avatar_url: Option<String>,
    pub role: &'static str,
    pub mfa_enrolled: bool,
}

pub async fn get_me(BearerUser(user): BearerUser) -> Result<Json<MeView>, HttpError> {
    Ok(Json(MeView {
        id: user.id.0.to_string(),
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        timezone: user.timezone,
        locale: user.locale,
        avatar_url: user.avatar_url,
        role: user.role.as_str(),
        mfa_enrolled: user.mfa_enrolled,
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileBody {
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    pub timezone: String,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

pub async fn update_profile(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
    Json(body): Json<UpdateProfileBody>,
) -> Result<Response, HttpError> {
    let first_name = normalize(body.first_name.as_deref());
    let last_name = normalize(body.last_name.as_deref());
    let avatar_url = normalize(body.avatar_url.as_deref());
    let tz = body.timezone.trim();
    if tz.is_empty() || tz.len() > 64 {
        return Err(HttpError(AuthError::InvalidRequest(
            "timezone: 1-64 chars".into(),
        )));
    }
    if let Some(url) = avatar_url.as_deref() {
        if url.len() > 1000 || !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(HttpError(AuthError::InvalidRequest(
                "avatar_url must be http(s) and <=1000 chars".into(),
            )));
        }
    }
    if let Some(n) = first_name.as_deref() {
        if n.len() > 100 {
            return Err(HttpError(AuthError::InvalidRequest(
                "first_name <=100 chars".into(),
            )));
        }
    }
    if let Some(n) = last_name.as_deref() {
        if n.len() > 100 {
            return Err(HttpError(AuthError::InvalidRequest(
                "last_name <=100 chars".into(),
            )));
        }
    }

    st.provider
        .users
        .update_profile(
            user.id,
            first_name.as_deref(),
            last_name.as_deref(),
            tz,
            avatar_url.as_deref(),
        )
        .await?;

    let _ = st
        .provider
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            None,
            AuditEvent::AdminAction {
                admin_id: user.id,
                action: "profile_updated".into(),
                target: user.id.0.to_string(),
            },
        )
        .await;

    Ok((StatusCode::OK, Json(json!({ "status": "ok" }))).into_response())
}

fn normalize(s: Option<&str>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordBody {
    pub current_password: String,
    pub new_password: String,
    pub password_confirmation: String,
}

/// `POST /v1/auth/me/password`
///
/// Verifies the current password, enforces the new-password policy,
/// rehashes, sets the new hash, audits `PasswordChanged`. Existing
/// sessions/refresh tokens are NOT booted here; that's the password-reset
/// path's posture. The user is voluntarily setting a new password while
/// signed in; revoking their own session would be user-hostile.
pub async fn change_password(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<ChangePasswordBody>,
) -> Result<Response, HttpError> {
    if body.new_password != body.password_confirmation {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "details": { "password_confirmation": "Passwords do not match" },
            })),
        )
            .into_response());
    }
    if let Err(e) =
        mokosh_auth_core::policy::validate_password_strength(&body.new_password, &user.email)
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "details": { "new_password": e.to_string() },
            })),
        )
            .into_response());
    }

    let stored = user.password_hash.as_deref().ok_or_else(|| {
        HttpError(AuthError::AccessDenied(
            "account has no password (federated only)".into(),
        ))
    })?;
    if !mokosh_auth_crypto::verify_password(&body.current_password, stored) {
        let _ = st
            .provider
            .audit
            .record(
                Some(user.tenant_id),
                Some(user.id),
                Some(addr.ip()),
                AuditEvent::LoginFailed {
                    email: user.email.clone(),
                    ip: Some(addr.ip().to_string()),
                    reason: "change_password_wrong_current".into(),
                },
            )
            .await;
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "details": { "current_password": "Current password is incorrect" },
            })),
        )
            .into_response());
    }

    let pw = body.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || mokosh_auth_crypto::hash_password(&pw))
        .await
        .map_err(|e| HttpError(AuthError::Internal(format!("argon2 join: {e}"))))?
        .map_err(|e| HttpError(AuthError::Crypto(format!("argon2: {e}"))))?;

    st.provider
        .users
        .set_password_hash(user.id, &new_hash)
        .await?;

    let _ = st
        .provider
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            Some(addr.ip()),
            AuditEvent::PasswordChanged { user_id: user.id },
        )
        .await;

    // Best-effort security alert (mirrors the MFA-disable path).
    if let Err(e) = st
        .mailer
        .send_security_alert(
            &user.email,
            "Your Mokosh password was changed",
            "Your account password was just changed.",
        )
        .await
    {
        tracing::error!(email = %user.email, "password-change alert email failed: {e}");
    }

    Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response())
}
