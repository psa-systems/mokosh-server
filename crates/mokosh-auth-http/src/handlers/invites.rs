//! Admin invites: issue, list, revoke, resend (admin-gated)
//! and lookup-by-token + accept (public).
//!
//! See `docs/mokosh-auth/02-backend-issuance.md` and `03-backend-
//! acceptance.md` for the full contract.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use mokosh_auth_core::{AuditEvent, AuthError, Invite, NewInvite, UserRole};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::email::display_name;
use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

/// Build the user-facing accept URL admins copy out of the UI when
/// SMTP is not configured: `<accept_base_url>/invite/<raw_token>`.
fn build_accept_url(base: &str, raw_token: &str) -> String {
    format!("{}/invite/{}", base.trim_end_matches('/'), raw_token)
}

const INVITE_TTL_DAYS: i64 = 7;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct IssueInviteBody {
    pub email: String,
    pub role: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct InviteView {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub invited_by: InvitedByView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct InvitedByView {
    pub id: Uuid,
    pub email: String,
}

#[derive(Deserialize)]
pub struct RevokeBody {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct AcceptInviteBody {
    /// Required for the `new_account` accept path (creates a fresh
    /// User). Ignored on the `join_tenant` path because the user
    /// already has a password.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn looks_like_email(s: &str) -> bool {
    // Lightweight sanity check: one '@', no whitespace, dot in the
    // domain. Mailer rejects malformed addresses at send time as the
    // authoritative validation.
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

fn invite_view(invite: Invite, inviter_email: String) -> InviteView {
    InviteView {
        id: invite.id,
        email: invite.email,
        role: invite.role.as_str().to_string(),
        issued_at: invite.issued_at,
        expires_at: invite.expires_at,
        invited_by: InvitedByView {
            id: invite.invited_by.0,
            email: inviter_email,
        },
        note: invite.note,
    }
}

fn parse_role(s: &str) -> Result<UserRole, HttpError> {
    // UserRole::parse rejects "super_admin" already (mokosh-auth's
    // canonical enum is admin/manager/finance/member/readonly; the
    // legacy public.users super_admin maps to admin via the bridge
    // migration). Any unknown string is invalid.
    UserRole::parse(s).ok_or_else(|| HttpError(AuthError::InvalidRequest("invalid role".into())))
}

fn require_admin(user: &mokosh_auth_core::User) -> Result<(), HttpError> {
    if matches!(user.role, UserRole::Admin) {
        Ok(())
    } else {
        Err(HttpError(AuthError::Forbidden(
            "only admins may manage invites".into(),
        )))
    }
}

fn invite_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": "invite_not_found"})),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

/// `POST /v1/auth/invites`
pub async fn issue(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Json(body): Json<IssueInviteBody>,
) -> Result<Response, HttpError> {
    require_admin(&admin)?;

    let email = body.email.trim().to_string();
    if !looks_like_email(&email) {
        return Err(HttpError(AuthError::InvalidRequest("invalid email".into())));
    }
    let role = parse_role(&body.role)?;
    if let Some(ref note) = body.note {
        if note.len() > 200 {
            return Err(HttpError(AuthError::InvalidRequest("note too long".into())));
        }
    }

    if let Err(rl) = st.rate_limiter.check_invite_issue(admin.id, &email) {
        return Ok(rl.into_response());
    }

    let raw_token = mokosh_auth_crypto::generate_opaque_token();
    let new_invite = NewInvite {
        tenant_id: admin.tenant_id,
        email: email.clone(),
        role,
        token: raw_token.clone(),
        invited_by: admin.id,
        expires_at: Utc::now() + Duration::days(INVITE_TTL_DAYS),
        note: body.note.clone(),
    };

    let invite = match st.invites.issue(new_invite).await {
        Ok(inv) => inv,
        Err(AuthError::Conflict(_)) => {
            let existing = st
                .invites
                .find_open_by_email(admin.tenant_id, &email)
                .await?;
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "invite_already_open",
                    "existing_invite_id": existing.map(|i| i.id),
                })),
            )
                .into_response());
        }
        Err(e) => return Err(HttpError(e)),
    };

    // Best-effort email send. If it fails, the row exists; admin can
    // resend. See 04-email.md for the rationale.
    let mail_warning = match st.mailer.send_invite(&invite, &raw_token, &admin).await {
        Ok(()) => None,
        Err(e) => {
            tracing::error!(invite_id = %invite.id, "invite email send failed: {e}");
            Some("email_send_failed")
        }
    };

    // Audit.
    let _ = st
        .provider
        .audit
        .record(
            Some(admin.tenant_id),
            Some(admin.id),
            None,
            AuditEvent::InviteIssued {
                invite_id: invite.id,
                tenant_id: admin.tenant_id,
                email: invite.email.clone(),
                role: invite.role,
                invited_by: admin.id,
            },
        )
        .await;

    let accept_url = build_accept_url(&st.accept_base_url, &raw_token);
    let mut body = json!({
        "invite": invite_view(invite, admin.email.clone()),
        // Returned so the issuing admin can copy a shareable link
        // directly out of the UI. SMTP delivery (when configured) is
        // additive; this stays the canonical recipe-of-record.
        "accept_url": accept_url,
    });
    if let Some(w) = mail_warning {
        body["warning"] = json!(w);
    }
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// `GET /v1/auth/invites` - list open invites for caller's tenant.
pub async fn list_open(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
) -> Result<Response, HttpError> {
    require_admin(&admin)?;

    let invites = st.invites.list_open(admin.tenant_id).await?;

    // Resolve invited_by emails. Batch in one query to avoid N+1.
    // Acceptable for phase 1; the open-invites list is small (<100).
    let mut views = Vec::with_capacity(invites.len());
    for invite in invites {
        let inviter_email = if invite.invited_by == admin.id {
            admin.email.clone()
        } else {
            st.provider
                .users
                .find_by_id(invite.invited_by)
                .await?
                .map(|u| u.email)
                .unwrap_or_else(|| "(unknown)".to_string())
        };
        views.push(invite_view(invite, inviter_email));
    }

    Ok((StatusCode::OK, Json(json!({ "invites": views }))).into_response())
}

/// `POST /v1/auth/invites/:invite_id/revoke`
pub async fn revoke(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(invite_id): Path<Uuid>,
    Json(body): Json<RevokeBody>,
) -> Result<Response, HttpError> {
    require_admin(&admin)?;

    // Cross-tenant probe -> 404. find_by_id is tenant-scoped.
    let invite = st
        .invites
        .find_by_id(invite_id, admin.tenant_id)
        .await?
        .ok_or(())
        .map_err(|_| HttpError(AuthError::NotFound))?;

    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("(no reason given)")
        .to_string();

    st.invites
        .revoke(invite.id, admin.tenant_id, admin.id, &reason)
        .await?;

    let _ = st
        .provider
        .audit
        .record(
            Some(admin.tenant_id),
            Some(admin.id),
            None,
            AuditEvent::InviteRevoked {
                invite_id: invite.id,
                revoked_by: admin.id,
                reason,
            },
        )
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /v1/auth/invites/:invite_id/resend` - new token, push expiry.
pub async fn resend(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(invite_id): Path<Uuid>,
) -> Result<Response, HttpError> {
    require_admin(&admin)?;

    let (invite, raw_token) = match st
        .invites
        .replace_token(invite_id, admin.tenant_id, INVITE_TTL_DAYS)
        .await
    {
        Ok(t) => t,
        Err(AuthError::NotFound) => return Err(HttpError(AuthError::NotFound)),
        Err(e) => return Err(HttpError(e)),
    };

    let mail_warning = match st.mailer.send_invite(&invite, &raw_token, &admin).await {
        Ok(()) => None,
        Err(e) => {
            tracing::error!(invite_id = %invite.id, "resend email send failed: {e}");
            Some("email_send_failed")
        }
    };

    let _ = st
        .provider
        .audit
        .record(
            Some(admin.tenant_id),
            Some(admin.id),
            None,
            AuditEvent::InviteIssued {
                invite_id: invite.id,
                tenant_id: admin.tenant_id,
                email: invite.email.clone(),
                role: invite.role,
                invited_by: admin.id,
            },
        )
        .await;

    let accept_url = build_accept_url(&st.accept_base_url, &raw_token);
    let mut body = json!({ "accept_url": accept_url });
    if let Some(w) = mail_warning {
        body["warning"] = json!(w);
    }
    Ok((StatusCode::OK, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// Public (token-gated) endpoints
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct InvitePreview {
    /// Discriminator the SPA branches on:
    ///   * `new_account` - no Mokosh user owns this email yet; the
    ///     accept page collects a password and creates the account.
    ///   * `join_tenant` - the email already belongs to an existing
    ///     user; accepting just adds a membership in the inviter's
    ///     tenant. The accept page shows a confirmation card and no
    ///     password field.
    pub kind: &'static str,
    pub email: String,
    pub role: String,
    pub tenant_name: String,
    pub invited_by_name: String,
    pub invited_by_email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Look up `email` across every tenant. Used by the invite-accept
/// flow to decide between the "create user" and "add membership"
/// branches. Returns the first match - email is now globally unique
/// (see migration 20260510000001) so there can be at most one.
async fn find_existing_user_by_email(
    st: &AuthHttpState,
    email: &str,
) -> Result<Option<mokosh_auth_core::User>, HttpError> {
    let mut matches = st
        .provider
        .users
        .find_by_email_globally(email)
        .await
        .map_err(HttpError)?;
    Ok(matches.pop())
}

/// `GET /v1/auth/invites/by-token/:token`
pub async fn read_by_token(
    State(st): State<Arc<AuthHttpState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
) -> Result<Response, HttpError> {
    if let Err(rl) = st.rate_limiter.check_invite_lookup(addr.ip(), &token) {
        return Ok(rl.into_response());
    }

    let invite = match st.invites.find_open_by_token(&token).await? {
        Some(inv) => inv,
        None => {
            let _ = st
                .provider
                .audit
                .record(
                    None,
                    None,
                    Some(addr.ip()),
                    AuditEvent::InviteAttemptFailed {
                        token_hash_prefix: token_hash_prefix(&token),
                        ip: Some(addr.ip().to_string()),
                        reason: "unknown".into(),
                    },
                )
                .await;
            return Ok(invite_not_found());
        }
    };

    let inviter = st
        .provider
        .users
        .find_by_id(invite.invited_by)
        .await?
        .ok_or_else(|| HttpError(AuthError::Internal("invited_by user missing".into())))?;
    let tenant_name = (st.tenant_name)(invite.tenant_id)
        .await
        .unwrap_or_else(|| "Mokosh".to_string());

    let kind = if find_existing_user_by_email(&st, &invite.email)
        .await?
        .is_some()
    {
        "join_tenant"
    } else {
        "new_account"
    };

    let preview = InvitePreview {
        kind,
        email: invite.email,
        role: invite.role.as_str().to_string(),
        tenant_name,
        invited_by_name: display_name(&inviter),
        invited_by_email: inviter.email,
        note: invite.note,
        expires_at: invite.expires_at,
    };
    Ok((StatusCode::OK, Json(preview)).into_response())
}

/// `POST /v1/auth/invites/by-token/:token/accept`
pub async fn accept_by_token(
    State(st): State<Arc<AuthHttpState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Json(body): Json<AcceptInviteBody>,
) -> Result<Response, HttpError> {
    if let Err(rl) = st.rate_limiter.check_invite_accept(addr.ip()) {
        return Ok(rl.into_response());
    }

    // Pre-load to surface a clean 404 vs 400 distinction; the
    // authoritative read happens inside the SERIALIZABLE accept tx.
    let invite = match st.invites.find_open_by_token(&token).await? {
        Some(inv) => inv,
        None => {
            let _ = st
                .provider
                .audit
                .record(
                    None,
                    None,
                    Some(addr.ip()),
                    AuditEvent::InviteAttemptFailed {
                        token_hash_prefix: token_hash_prefix(&token),
                        ip: Some(addr.ip().to_string()),
                        reason: "unknown".into(),
                    },
                )
                .await;
            return Ok(invite_not_found());
        }
    };

    // Branch on whether a user already owns this email globally. The
    // `find_existing_user_by_email` lookup is best-effort here; the
    // SERIALIZABLE accept_* tx re-checks all invariants under lock.
    let existing = find_existing_user_by_email(&st, &invite.email).await?;

    let user = if let Some(target) = existing {
        // join_tenant path: no password, just create a membership.
        match st.invites.accept_existing(&token, target.id).await {
            Ok(u) => u,
            Err(AuthError::NotFound) | Err(AuthError::InvalidGrant(_)) => {
                return Ok(invite_not_found());
            }
            Err(AuthError::Conflict(msg)) => {
                // (user_id, tenant_id) PK collision OR
                // "invite already used" - either way the right thing
                // for the SPA is "you're already in this tenant /
                // the link's already been used; sign in".
                let _ = st
                    .provider
                    .audit
                    .record(
                        Some(invite.tenant_id),
                        Some(target.id),
                        Some(addr.ip()),
                        AuditEvent::InviteAttemptFailed {
                            token_hash_prefix: token_hash_prefix(&token),
                            ip: Some(addr.ip().to_string()),
                            reason: format!("conflict: {msg}"),
                        },
                    )
                    .await;
                return Ok((
                    StatusCode::CONFLICT,
                    Json(json!({"error": "invite_already_used"})),
                )
                    .into_response());
            }
            Err(e) => return Err(HttpError(e)),
        }
    } else {
        // new_account path: validate + hash password, create user
        // (existing flow).
        let password = body.password.as_deref().unwrap_or("");
        if let Err(e) =
            mokosh_auth_core::policy::validate_password_strength(password, &invite.email)
        {
            let _ = st
                .provider
                .audit
                .record(
                    Some(invite.tenant_id),
                    None,
                    Some(addr.ip()),
                    AuditEvent::InviteAttemptFailed {
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

        let pw = password.to_string();
        let hash = tokio::task::spawn_blocking(move || mokosh_auth_crypto::hash_password(&pw))
            .await
            .map_err(|e| HttpError(AuthError::Internal(format!("argon2 join: {e}"))))?
            .map_err(|e| HttpError(AuthError::Crypto(format!("argon2: {e}"))))?;

        let first_name = body
            .first_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let last_name = body
            .last_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        match st
            .invites
            .accept(&token, &hash, first_name, last_name)
            .await
        {
            Ok(u) => u,
            Err(AuthError::NotFound) | Err(AuthError::InvalidGrant(_)) => {
                return Ok(invite_not_found());
            }
            Err(AuthError::Conflict(_)) => {
                return Ok((
                    StatusCode::CONFLICT,
                    Json(json!({"error": "invite_already_used"})),
                )
                    .into_response());
            }
            Err(e) => return Err(HttpError(e)),
        }
    };

    // The tenant membership is created atomically inside the
    // SERIALIZABLE invite-accept tx (see `accept_once` in
    // mokosh-auth-storage), with the org-role derived from the invite
    // role. Creating it here fire-and-forget left a crash window where
    // the user existed with no membership, and hardcoded org_role=Admin
    // over-privileged Member/ReadOnly invites.

    let _ = st
        .provider
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            Some(addr.ip()),
            AuditEvent::InviteAccepted {
                invite_id: invite.id,
                new_user_id: user.id,
                tenant_id: user.tenant_id,
                email: user.email.clone(),
                role: user.role,
            },
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "user_id": user.id,
            "email": user.email,
            "redirect_to": "/login",
        })),
    )
        .into_response())
}
