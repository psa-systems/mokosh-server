//! `/v1/auth/password-reset` - request + complete. Public endpoints
//! (no Bearer); enumeration-resistant on `start`; SERIALIZABLE on
//! `complete` (boots every active session for the user on success).
//!
//! See docs/mokosh-smtp/05-password-reset.md.

use crate::handlers::shared::{looks_like_email, token_hash_prefix};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use mokosh_auth_core::{AuditEvent, AuthError, NewPasswordResetToken};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::router::AuthHttpState;

/// Token TTL in hours. Shorter than invites (7 days) and signup
/// (24 hours) because a leaked reset token overrides an existing
/// account's credentials. 1 hour is the standard.
const RESET_TOKEN_TTL_HOURS: i64 = 1;

#[derive(Debug, Deserialize)]
pub struct StartBody {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct StartResponse {
    /// Hardcoded "ok": body MUST NOT differ between "email known" and
    /// "email unknown" so a caller cannot enumerate accounts.
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ResetPreview {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct CompleteBody {
    pub password: String,
    pub password_confirmation: String,
}

#[derive(Debug, Serialize)]
pub struct CompleteResponse {
    pub user_id: String,
    pub redirect_to: String,
}

fn reset_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "reset_not_found" })),
    )
        .into_response()
}

/// `POST /v1/auth/password-reset`
///
/// Always returns 200 on reachable paths (rate limit is the only
/// non-200). Body never reveals whether the email is registered.
pub async fn start(
    State(st): State<Arc<AuthHttpState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<StartBody>,
) -> Result<Response, HttpError> {
    let email = body.email.trim().to_string();
    if !looks_like_email(&email) {
        // Format-level error is observable from the input syntax;
        // surfacing it doesn't leak account state.
        return Err(HttpError(AuthError::InvalidRequest("invalid email".into())));
    }

    if let Err(rl) = st
        .rate_limiter
        .check_password_reset_start(addr.ip(), &email)
    {
        return Ok(rl.into_response());
    }

    let now = Utc::now();

    // No user? Audit and return success.
    let existing = st.provider.users.find_by_email_globally(&email).await?;
    if existing.is_empty() {
        let _ = st
            .provider
            .audit
            .record(
                None,
                None,
                Some(addr.ip()),
                AuditEvent::PasswordResetRequested {
                    email: email.clone(),
                    ip: Some(addr.ip().to_string()),
                },
            )
            .await;
        return Ok((StatusCode::OK, Json(StartResponse { status: "ok" })).into_response());
    }

    // Coalesce repeat requests within the TTL window so a retry storm
    // does not spam the recipient's inbox.
    if st
        .password_reset_tokens
        .find_open_by_email(&email, now)
        .await?
        .is_some()
    {
        return Ok((StatusCode::OK, Json(StartResponse { status: "ok" })).into_response());
    }

    let raw_token = mokosh_auth_crypto::generate_opaque_token();
    let token_hash = mokosh_auth_crypto::hash_opaque_token(&raw_token);
    st.password_reset_tokens
        .issue(NewPasswordResetToken {
            email: email.clone(),
            token_hash,
            expires_at: now + Duration::hours(RESET_TOKEN_TTL_HOURS),
        })
        .await?;

    if let Err(e) = st.mailer.send_password_reset(&email, &raw_token).await {
        tracing::error!(email = %email, "password-reset email send failed: {e}");
    }

    let _ = st
        .provider
        .audit
        .record(
            None,
            None,
            Some(addr.ip()),
            AuditEvent::PasswordResetRequested {
                email,
                ip: Some(addr.ip().to_string()),
            },
        )
        .await;

    Ok((StatusCode::OK, Json(StartResponse { status: "ok" })).into_response())
}

/// `GET /v1/auth/password-reset/by-token/{token}`
pub async fn preview(
    State(st): State<Arc<AuthHttpState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
) -> Result<Response, HttpError> {
    let token_hash = mokosh_auth_crypto::hash_opaque_token(&token);
    let now = Utc::now();
    match st
        .password_reset_tokens
        .find_by_token_hash(token_hash)
        .await?
    {
        Some(t) if t.is_open(now) => {
            Ok((StatusCode::OK, Json(ResetPreview { email: t.email })).into_response())
        }
        _ => {
            let _ = st
                .provider
                .audit
                .record(
                    None,
                    None,
                    Some(addr.ip()),
                    AuditEvent::PasswordResetAttemptFailed {
                        token_hash_prefix: token_hash_prefix(&token),
                        ip: Some(addr.ip().to_string()),
                        reason: "unknown_or_used_or_expired".into(),
                    },
                )
                .await;
            Ok(reset_not_found())
        }
    }
}

/// `POST /v1/auth/password-reset/by-token/{token}/complete`
pub async fn complete(
    State(st): State<Arc<AuthHttpState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Json(body): Json<CompleteBody>,
) -> Result<Response, HttpError> {
    if let Err(rl) = st.rate_limiter.check_password_reset_complete(addr.ip()) {
        return Ok(rl.into_response());
    }

    let token_hash = mokosh_auth_crypto::hash_opaque_token(&token);

    // Pre-check: avoid running argon2 against a clearly-dead token.
    // The SERIALIZABLE complete re-checks under lock; this is just
    // an optimization that surfaces the common bad-token case fast.
    let now = Utc::now();
    let preview = st
        .password_reset_tokens
        .find_by_token_hash(token_hash)
        .await?;
    if !preview.as_ref().map(|t| t.is_open(now)).unwrap_or(false) {
        let _ = st
            .provider
            .audit
            .record(
                None,
                None,
                Some(addr.ip()),
                AuditEvent::PasswordResetAttemptFailed {
                    token_hash_prefix: token_hash_prefix(&token),
                    ip: Some(addr.ip().to_string()),
                    reason: "unknown_or_used_or_expired".into(),
                },
            )
            .await;
        return Ok(reset_not_found());
    }
    let target_email = preview.unwrap().email;

    // Confirmation match first: cheap equality check before the password
    // policy + argon2 work, and a mismatch should never trigger an
    // expensive hash or leak policy details about a password the user
    // did not intend to set.
    if body.password != body.password_confirmation {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "details": { "password_confirmation": "Passwords do not match" },
            })),
        )
            .into_response());
    }

    // Password policy.
    if let Err(e) =
        mokosh_auth_core::policy::validate_password_strength(&body.password, &target_email)
    {
        let _ = st
            .provider
            .audit
            .record(
                None,
                None,
                Some(addr.ip()),
                AuditEvent::PasswordResetAttemptFailed {
                    token_hash_prefix: token_hash_prefix(&token),
                    ip: Some(addr.ip().to_string()),
                    reason: "weak_password".into(),
                },
            )
            .await;
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "details": { "password": e.to_string() },
            })),
        )
            .into_response());
    }

    // argon2 off the I/O thread.
    let pw = body.password.clone();
    let hash = tokio::task::spawn_blocking(move || mokosh_auth_crypto::hash_password(&pw))
        .await
        .map_err(|e| HttpError(AuthError::Internal(format!("argon2 join: {e}"))))?
        .map_err(|e| HttpError(AuthError::Crypto(format!("argon2: {e}"))))?;

    // SERIALIZABLE complete: validates the token under lock, updates
    // the password, marks the token used, and revokes every active
    // session + refresh family for the user. All-or-nothing.
    let user_id = match st.password_reset_tokens.complete(token_hash, &hash).await {
        Ok(uid) => uid,
        Err(AuthError::NotFound) => {
            let _ = st
                .provider
                .audit
                .record(
                    None,
                    None,
                    Some(addr.ip()),
                    AuditEvent::PasswordResetAttemptFailed {
                        token_hash_prefix: token_hash_prefix(&token),
                        ip: Some(addr.ip().to_string()),
                        reason: "race_lost_or_user_gone".into(),
                    },
                )
                .await;
            return Ok(reset_not_found());
        }
        Err(e) => return Err(HttpError(e)),
    };

    let _ = st
        .provider
        .audit
        .record(
            None,
            Some(user_id),
            Some(addr.ip()),
            AuditEvent::PasswordResetCompleted {
                user_id,
                ip: Some(addr.ip().to_string()),
            },
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(CompleteResponse {
            user_id: user_id.0.to_string(),
            redirect_to: "/login".to_string(),
        }),
    )
        .into_response())
}
