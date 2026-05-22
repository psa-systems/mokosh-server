//! `/v1/feedback` (public submit) + `/v1/admin/feedback` (admin triage).
//!
//! See docs/mokosh-fixes/04-feedback-inbox.md. The SPA wires this end
//! to end already; this file is the server side that was missing.
//!
//! - `POST /v1/feedback`           - anonymous OK. Bearer (if present)
//!                                    pins `submitter_id` + overrides
//!                                    the client-supplied name/email
//!                                    so submitters can't spoof identity.
//! - `GET  /v1/admin/feedback`     - admin-gated. Bare array (SPA shape).
//!                                    `?status=new|triaged|closed` filters.
//! - `PATCH /v1/admin/feedback/:id` - admin-gated. Body `{status}`. Writes
//!                                    an `AdminAction` audit row.

// The module-doc route list above is intentionally column-aligned.
#![allow(clippy::doc_overindented_list_items)]

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use mokosh_auth_core::{
    AuditEvent, AuthError, Feedback, FeedbackStatus, NewFeedback, TenantId, UserId, UserRole,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

const MAX_MESSAGE_LEN: usize = 8000;
const MAX_SUBJECT_LEN: usize = 200;
const MAX_TAG_LEN: usize = 40;
const MAX_TAGS: usize = 8;

// --- Wire shapes --------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct SubmitBody {
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    /// Honeypot: legitimate submissions leave this empty. Bots filling
    /// every input on the form get silently dropped (we still 200 so
    /// the bot doesn't learn the signal).
    #[serde(default)]
    pub website: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FeedbackAttachmentView {
    pub filename: String,
    pub size: u64,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct FeedbackView {
    pub id: String,
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    pub attachments: Vec<FeedbackAttachmentView>,
    pub forgejo_issue_url: Option<String>,
    pub status: FeedbackStatus,
    pub created_at: DateTime<Utc>,
}

impl From<Feedback> for FeedbackView {
    fn from(f: Feedback) -> Self {
        Self {
            id: f.id.to_string(),
            user_id: f.submitter_id.map(|u| u.0.to_string()),
            org_id: f.tenant_id.map(|t| t.0.to_string()),
            name: f.submitter_name,
            email: f.submitter_email,
            subject: f.subject,
            tags: f.tags,
            message: f.message,
            page_path: f.page_path,
            attachments: Vec::new(),
            forgejo_issue_url: f.forgejo_issue_url,
            status: f.status,
            created_at: f.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusBody {
    pub status: FeedbackStatus,
}

// --- Helpers ------------------------------------------------------------

fn require_admin(role: UserRole) -> Result<(), HttpError> {
    if matches!(role, UserRole::Admin) {
        Ok(())
    } else {
        Err(HttpError(AuthError::Forbidden(
            "admin role required".into(),
        )))
    }
}

/// Decode a Bearer access token without enforcing auth on the route.
/// Returns `None` if the header is absent or the token is malformed /
/// untrusted; `Some(user)` if the token verifies. The public submit
/// endpoint uses this to opt-into "if signed in, pin submitter_id" so
/// authed callers can't spoof someone else's name/email.
async fn maybe_bearer_user(
    st: &Arc<AuthHttpState>,
    headers: &HeaderMap,
) -> Option<mokosh_auth_core::User> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?
        .trim();
    let header_data = decode_header(token).ok()?;
    let kid = header_data.kid?;
    let dk = st.provider.keys.decoding_key(&kid)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.set_issuer(&[st.provider.cfg.issuer_str().trim_end_matches('/')]);
    let data = decode::<serde_json::Value>(token, dk, &validation).ok()?;
    let sub = data.claims.get("sub")?.as_str()?;
    let uid = uuid::Uuid::parse_str(sub).ok()?;
    st.provider
        .users
        .find_by_id(UserId(uid))
        .await
        .ok()
        .flatten()
}

// --- Handlers -----------------------------------------------------------

/// POST /v1/feedback. Anonymous OK.
pub async fn submit(
    State(st): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<SubmitBody>,
) -> Result<(StatusCode, Json<FeedbackView>), HttpError> {
    // Honeypot: silently accept-and-drop on filled trap.
    if body
        .website
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        // 202 Accepted + a fake-looking row would leak the signal; we
        // 201 with a synthetic empty body that looks like a real
        // accept. The row never lands in the DB.
        return Ok((
            StatusCode::CREATED,
            Json(FeedbackView {
                id: uuid::Uuid::new_v4().to_string(),
                user_id: None,
                org_id: None,
                name: None,
                email: None,
                subject: None,
                tags: vec![],
                message: String::new(),
                page_path: body.page_path,
                attachments: vec![],
                forgejo_issue_url: None,
                status: FeedbackStatus::New,
                created_at: Utc::now(),
            }),
        ));
    }

    let message = body.message.trim().to_string();
    if message.is_empty() || message.len() > MAX_MESSAGE_LEN {
        return Err(HttpError(AuthError::InvalidRequest(format!(
            "message: 1-{MAX_MESSAGE_LEN} chars"
        ))));
    }
    let subject = body
        .subject
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.len() > MAX_SUBJECT_LEN {
                s[..MAX_SUBJECT_LEN].to_string()
            } else {
                s.to_string()
            }
        });
    let tags: Vec<String> = body
        .tags
        .into_iter()
        .filter_map(|t| {
            let t = t.trim().to_string();
            (!t.is_empty() && t.len() <= MAX_TAG_LEN).then_some(t)
        })
        .take(MAX_TAGS)
        .collect();

    let me = maybe_bearer_user(&st, &headers).await;
    let (submitter_id, submitter_name, submitter_email, tenant_id) = match me {
        Some(u) => {
            let name = match (u.first_name.as_deref(), u.last_name.as_deref()) {
                (Some(f), Some(l)) => Some(format!("{f} {l}")),
                (Some(f), None) => Some(f.to_string()),
                (None, Some(l)) => Some(l.to_string()),
                _ => None,
            };
            (Some(u.id), name, Some(u.email), Some(u.tenant_id))
        }
        None => (
            None,
            body.name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            body.email
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            None::<TenantId>,
        ),
    };

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let row = st
        .feedback
        .submit(NewFeedback {
            tenant_id,
            submitter_id,
            submitter_name,
            submitter_email,
            subject,
            message,
            tags,
            page_path: body.page_path,
            user_agent: ua,
            ip: Some(addr.ip()),
        })
        .await
        .map_err(HttpError)?;

    Ok((StatusCode::CREATED, Json(FeedbackView::from(row))))
}

/// GET /v1/admin/feedback?status=...
pub async fn list_admin(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<FeedbackView>>, HttpError> {
    require_admin(admin.role)?;
    let status = q
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            FeedbackStatus::parse(s).ok_or_else(|| {
                HttpError(AuthError::InvalidRequest(format!(
                    "status: must be new|triaged|closed, got '{s}'"
                )))
            })
        })
        .transpose()?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0);

    // Platform Admin sees every tenant's feedback plus anonymous rows
    // (passed as tenant_id=None to the repo).
    let (rows, _total) = st
        .feedback
        .list_filtered(None, status, limit, offset)
        .await
        .map_err(HttpError)?;
    Ok(Json(rows.into_iter().map(FeedbackView::from).collect()))
}

/// PATCH /v1/admin/feedback/:id - update status.
pub async fn update_status(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UpdateStatusBody>,
) -> Result<Response, HttpError> {
    require_admin(admin.role)?;
    st.feedback
        .set_status(id, body.status, admin.id)
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
                action: format!("feedback.status_changed:{}", body.status.as_str()),
                target: id.to_string(),
            },
        )
        .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}
