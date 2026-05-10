//! Self-signup. Public (no Bearer) endpoints that create a user
//! account plus a personal tenant for them.
//!
//! Three handlers:
//!   * `start`    POST /v1/auth/signup                          : sends the email link
//!   * `preview`  GET  /v1/auth/signup/by-token/{token}         : returns { email }
//!   * `complete` POST /v1/auth/signup/by-token/{token}/complete: sets password, creates account
//!
//! Enumeration resistance: `start` returns 200 whether or not the
//! email is in use; the body is identical. The /by-token/* endpoints
//! collapse unknown / used / expired into one 404 with
//! `{"error":"signup_not_found"}` so the recipient cannot tell which
//! state from the outside. Audit events record the prefix of the
//! token hash, never the raw token.
//!
//! Phase 2 of docs/mokosh-auth/10-memberships-and-self-signup.md.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use mokosh_auth_core::{
    AuditEvent, AuthError, MembershipStatus, NewMembership, NewSignupToken, NewUser, UserId,
    UserRole, UserStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::router::AuthHttpState;

const SIGNUP_TOKEN_TTL_HOURS: i64 = 24;

#[derive(Debug, Deserialize)]
pub struct StartBody {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct StartResponse {
    /// Hardcoded "ok": the body must not differ between "email
    /// accepted" and "email already in use" so the client cannot tell
    /// from the response.
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SignupPreview {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct CompleteBody {
    pub password: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CompleteResponse {
    pub user_id: String,
    pub tenant_id: String,
    /// SPA hint for where to send the user after the success card. The
    /// canonical path is `/login`; the SPA does not have to obey but
    /// having the value here keeps the redirect logic out of every
    /// handler that creates a user.
    pub redirect_to: String,
}

fn looks_like_email(s: &str) -> bool {
    let s = s.trim();
    let mut at = s.split('@');
    match (at.next(), at.next(), at.next()) {
        (Some(local), Some(domain), None) => {
            !local.is_empty()
                && !s.chars().any(char::is_whitespace)
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        _ => false,
    }
}

fn token_hash_prefix(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let bytes = h.finalize();
    bytes[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

fn signup_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "signup_not_found" })),
    )
        .into_response()
}

fn feature_disabled() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "signup_disabled" })),
    )
        .into_response()
}

/// `POST /v1/auth/signup`
///
/// Always returns 200 on success-shaped paths (rate limit hit is the
/// only non-200 from the live deployment). The body never reveals
/// whether the email was new, in use, or already had an open token.
pub async fn start(
    State(st): State<Arc<AuthHttpState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<StartBody>,
) -> Result<Response, HttpError> {
    if !st.public_signup_enabled {
        return Ok(feature_disabled());
    }

    let email = body.email.trim().to_string();
    if !looks_like_email(&email) {
        // Format-level rejection is fine to surface; it is observable
        // anyway from the syntax of the input.
        return Err(HttpError(AuthError::InvalidRequest("invalid email".into())));
    }

    if let Err(rl) = st.rate_limiter.check_signup_start(addr.ip(), &email) {
        return Ok(rl.into_response());
    }

    let now = Utc::now();

    // Existing user? Same response shape, but audit the attempt and
    // do nothing else. The recipient sees the same 200; the side
    // channel is the email (which never lands).
    let existing = st.provider.users.find_by_email_globally(&email).await?;
    if !existing.is_empty() {
        let _ = st
            .provider
            .audit
            .record(
                None,
                None,
                Some(addr.ip()),
                AuditEvent::SignupRequested {
                    email: email.clone(),
                    ip: Some(addr.ip().to_string()),
                },
            )
            .await;
        return Ok((
            StatusCode::OK,
            Json(StartResponse { status: "ok" }),
        )
            .into_response());
    }

    // Coalesce repeat requests for the same email if we already have
    // an open token. Avoid spamming inboxes on a refresh-the-form
    // attack.
    if st
        .signup_tokens
        .find_open_by_email(&email, now)
        .await?
        .is_some()
    {
        return Ok((
            StatusCode::OK,
            Json(StartResponse { status: "ok" }),
        )
            .into_response());
    }

    let raw_token = mokosh_auth_crypto::generate_opaque_token();
    let token_hash = mokosh_auth_crypto::hash_opaque_token(&raw_token);
    st.signup_tokens
        .issue(NewSignupToken {
            email: email.clone(),
            token_hash,
            expires_at: now + Duration::hours(SIGNUP_TOKEN_TTL_HOURS),
        })
        .await?;

    if let Err(e) = st.mailer.send_signup(&email, &raw_token).await {
        // Best-effort: row exists, the user can request again.
        tracing::error!(email = %email, "signup email send failed: {e}");
    }

    let _ = st
        .provider
        .audit
        .record(
            None,
            None,
            Some(addr.ip()),
            AuditEvent::SignupRequested {
                email,
                ip: Some(addr.ip().to_string()),
            },
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(StartResponse { status: "ok" }),
    )
        .into_response())
}

/// `GET /v1/auth/signup/by-token/{token}`
pub async fn preview(
    State(st): State<Arc<AuthHttpState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
) -> Result<Response, HttpError> {
    if !st.public_signup_enabled {
        return Ok(feature_disabled());
    }

    let token_hash = mokosh_auth_crypto::hash_opaque_token(&token);
    let now = Utc::now();
    match st.signup_tokens.find_by_token_hash(token_hash).await? {
        Some(t) if t.is_open(now) => Ok((
            StatusCode::OK,
            Json(SignupPreview { email: t.email }),
        )
            .into_response()),
        _ => {
            let _ = st
                .provider
                .audit
                .record(
                    None,
                    None,
                    Some(addr.ip()),
                    AuditEvent::SignupAttemptFailed {
                        token_hash_prefix: token_hash_prefix(&token),
                        ip: Some(addr.ip().to_string()),
                        reason: "unknown_or_used_or_expired".into(),
                    },
                )
                .await;
            Ok(signup_not_found())
        }
    }
}

/// `POST /v1/auth/signup/by-token/{token}/complete`
pub async fn complete(
    State(st): State<Arc<AuthHttpState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Json(body): Json<CompleteBody>,
) -> Result<Response, HttpError> {
    if !st.public_signup_enabled {
        return Ok(feature_disabled());
    }

    let token_hash = mokosh_auth_crypto::hash_opaque_token(&token);
    let now = Utc::now();

    // 1. Resolve and gate the token.
    let signup = match st.signup_tokens.find_by_token_hash(token_hash).await? {
        Some(t) if t.is_open(now) => t,
        _ => {
            let _ = st
                .provider
                .audit
                .record(
                    None,
                    None,
                    Some(addr.ip()),
                    AuditEvent::SignupAttemptFailed {
                        token_hash_prefix: token_hash_prefix(&token),
                        ip: Some(addr.ip().to_string()),
                        reason: "unknown_or_used_or_expired".into(),
                    },
                )
                .await;
            return Ok(signup_not_found());
        }
    };

    // 2. Password policy. Same helper invite-accept uses; consistent
    //    error shape so SPAs can render the same field-error UI.
    if let Err(e) =
        mokosh_auth_core::policy::validate_password_strength(&body.password, &signup.email)
    {
        let _ = st
            .provider
            .audit
            .record(
                None,
                None,
                Some(addr.ip()),
                AuditEvent::SignupAttemptFailed {
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

    let pw = body.password.clone();
    let hash = tokio::task::spawn_blocking(move || mokosh_auth_crypto::hash_password(&pw))
        .await
        .map_err(|e| HttpError(AuthError::Internal(format!("password hash join: {e}"))))?
        .map_err(|e| HttpError(AuthError::Crypto(e.to_string())))?;

    // 3. Create the personal tenant first (cross-schema, can't be in
    //    the auth-schema tx). On any downstream failure we keep the
    //    orphan tenant row; cheap to clean up later, no security
    //    implication. Phase 2 ships with this; SERIALIZABLE atomicity
    //    across the whole flow is a phase-3+ refinement.
    let tenant_id = (st.create_personal_tenant)(signup.email.clone()).await?;

    // 4. Create the user inside the auth schema. The global email
    //    uniqueness constraint added in 20260510000001 catches any
    //    race where two completion requests for the same token
    //    arrive at once (the second hits a unique-violation and we
    //    surface 409).
    let new_user = NewUser {
        tenant_id,
        email: signup.email.clone(),
        password_hash: Some(hash),
        role: UserRole::Admin,
        status: UserStatus::Active,
        first_name: body.first_name.clone(),
        last_name: body.last_name.clone(),
    };
    let user = st.provider.users.create(new_user).await?;
    // status=Active does not auto-set email_verified_at on the
    // standard `create`; do it explicitly. Clicking the email link
    // demonstrates inbox control - we treat that as verification.
    let _ = st.provider.users.mark_email_verified(user.id, now).await;

    // 5. Owner membership of the personal tenant.
    let _ = st
        .memberships
        .create(NewMembership {
            user_id: user.id,
            tenant_id,
            role: UserRole::Admin,
            status: MembershipStatus::Active,
        })
        .await?;

    // 6. Mark token used. The mark_used `WHERE used_at IS NULL` race
    //    guard returns NotFound on a double-redeem; if the user row
    //    above already exists from a prior race the unique-email
    //    catch will have surfaced first. Either way the system stays
    //    consistent.
    if let Err(e) = st.signup_tokens.mark_used(token_hash, user.id, now).await {
        tracing::warn!(user_id = %user.id, "signup token mark_used failed (post-create): {e}");
    }

    let _ = st
        .provider
        .audit
        .record(
            Some(tenant_id),
            Some(user.id),
            Some(addr.ip()),
            AuditEvent::SignupCompleted {
                user_id: user.id,
                tenant_id,
                email: signup.email.clone(),
            },
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(CompleteResponse {
            user_id: user.id.0.to_string(),
            tenant_id: tenant_id.0.to_string(),
            redirect_to: "/login".to_string(),
        }),
    )
        .into_response())
}

// Suppresses the unused-import warning on the bin target where
// SignupTokenRepository is reachable through Arc<dyn ...>.
#[allow(dead_code)]
fn _enforce_user_id_used(_id: UserId) {}
