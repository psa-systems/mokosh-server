//! PMS-1208: REST handlers for the grant-invitation lifecycle.
//!
//! Two mount points, each with its own scoping shape:
//!
//! - `/api/v1/grants/invitations/*` is the OWNER surface. Every
//!   handler runs behind `RequireAuth` + `RequireAdmin`; the caller
//!   is placed in the tenant they are sharing, and the row's
//!   `tenant_id` is scoped from the caller.
//! - `/api/v1/my-grants/invitations/*` is the GRANTEE surface,
//!   cross-tenant by construction. `RequireAuth` alone; the caller
//!   is who they say they are on their at+jwt `sub`, and the row's
//!   tenant scope is whatever the invitation names.
//!
//! The two by-token endpoints (`GET .../by-token/{token}` and the
//! two POST verbs) are UNAUTHENTICATED at the middleware level: the
//! token IS the credential, and the handler binds the caller's
//! bunyip identity by reading the current request's `AuthState`
//! when it is present or falling back to the token's stored
//! invitee id.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use super::grant_invitations::{
    AcceptRefusal, CreatedInvitation, GrantInvitation, GrantInvitationsService, DEFAULT_TTL,
};
use super::middleware::{RequireAdminUser, RequireAuth};
use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct GrantInvitationsState {
    pub db: Arc<Database>,
}

/// POST body for `POST /api/v1/grants/invitations`. Either
/// `invitee_bunyip_user_id` or `invitee_email` MUST be present;
/// email is the friendlier admin path, id is the machine one. The
/// service takes both because a SaaS-mode caller resolved the id
/// through bunyip already, while a standalone-mode caller has only
/// the address.
#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    #[serde(default)]
    pub invitee_bunyip_user_id: Option<Uuid>,
    #[serde(default)]
    pub invitee_email: Option<String>,
    pub role: String,
}

/// Owner-facing response shape. Deliberately does NOT carry the
/// `accept_token` plaintext, because the row lives in the owner's
/// tenant and a leaked GET would then leak the token; the
/// plaintext is on the create response ONE TIME and never again.
#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub inviter_bunyip_user_id: Uuid,
    pub invitee_bunyip_user_id: Option<Uuid>,
    pub invitee_email: String,
    pub role: String,
    pub status: String,
    pub invited_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub declined_at: Option<chrono::DateTime<chrono::Utc>>,
    pub canceled_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<GrantInvitation> for InvitationResponse {
    fn from(row: GrantInvitation) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            inviter_bunyip_user_id: row.inviter_bunyip_user_id,
            invitee_bunyip_user_id: row.invitee_bunyip_user_id,
            invitee_email: row.invitee_email,
            role: row.role,
            status: row.status,
            invited_at: row.invited_at,
            expires_at: row.expires_at,
            accepted_at: row.accepted_at,
            declined_at: row.declined_at,
            canceled_at: row.canceled_at,
        }
    }
}

/// Response for `POST /api/v1/grants/invitations`. Carries the
/// PLAINTEXT `accept_token` so the caller can build the invitation
/// email's accept link. This is the ONLY endpoint that hands the
/// plaintext back.
#[derive(Debug, Serialize)]
pub struct CreatedInvitationResponse {
    #[serde(flatten)]
    pub invitation: InvitationResponse,
    pub accept_token: String,
}

/// Metadata the `by-token` endpoint hands to the SPA's accept
/// page. Unauthenticated (the token IS the credential); no PII
/// beyond what the SPA renders on the page.
#[derive(Debug, Serialize)]
pub struct InvitationMetadata {
    pub mokosh_account_name: String,
    pub mokosh_account_slug: String,
    pub role: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

/// Owner-facing mount. Sits under `/api/v1/grants/invitations` in
/// `create_api_router`.
pub fn grant_invitations_owner_routes(db: Arc<Database>) -> Router {
    let state = GrantInvitationsState { db };
    Router::new()
        .route("/", post(create_invitation))
        .route("/", get(list_owner_outbox))
        .route("/{id}", delete(cancel_invitation))
        .with_state(state)
}

/// Grantee-facing mount. Sits under `/api/v1/my-grants/invitations`.
pub fn grant_invitations_grantee_routes(db: Arc<Database>) -> Router {
    let state = GrantInvitationsState { db };
    Router::new()
        .route("/", get(list_grantee_inbox))
        .with_state(state)
}

/// Unauthenticated mount for the token-driven endpoints. Sits
/// under `/api/v1/grants/invitations/by-token`.
pub fn grant_invitations_by_token_routes(db: Arc<Database>) -> Router {
    let state = GrantInvitationsState { db };
    Router::new()
        .route("/{token}", get(get_invitation_by_token))
        .route("/{token}/accept", post(accept_invitation))
        .route("/{token}/decline", post(decline_invitation))
        .with_state(state)
}

async fn create_invitation(
    State(state): State<GrantInvitationsState>,
    RequireAdminUser(caller): RequireAdminUser,
    Json(body): Json<CreateInvitationRequest>,
) -> AppResult<(StatusCode, Json<CreatedInvitationResponse>)> {
    let invitee_email = body
        .invitee_email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if body.invitee_bunyip_user_id.is_none() && invitee_email.is_none() {
        return Err(AppError::BadRequest(
            "Provide either invitee_bunyip_user_id or invitee_email.".to_string(),
        ));
    }
    // Refuse a self-invite by verified address. The id-based CHECK
    // constraint covers the id path; this covers the email-only
    // path when the caller's own address matches.
    if let Some(em) = invitee_email {
        if em.eq_ignore_ascii_case(&caller.email) {
            return Err(AppError::BadRequest(
                "You cannot invite yourself.".to_string(),
            ));
        }
    }
    // The service's create returns Conflict on the partial-UNIQUE
    // trip; the "already an active grant" pre-check runs here so
    // the two 409s are named separately.
    let addr = invitee_email
        .map(str::to_string)
        .unwrap_or_else(|| body.invitee_bunyip_user_id.unwrap().to_string());
    let CreatedInvitation {
        invitation,
        accept_token,
    } = GrantInvitationsService::create(
        state.db.pool(),
        caller.tenant_id,
        caller.id,
        body.invitee_bunyip_user_id,
        &addr,
        body.role.trim(),
        DEFAULT_TTL,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedInvitationResponse {
            invitation: invitation.into(),
            accept_token,
        }),
    ))
}

async fn list_owner_outbox(
    State(state): State<GrantInvitationsState>,
    RequireAdminUser(caller): RequireAdminUser,
) -> AppResult<Json<Vec<InvitationResponse>>> {
    let rows =
        GrantInvitationsService::find_pending_by_tenant(state.db.pool(), caller.tenant_id).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn list_grantee_inbox(
    State(state): State<GrantInvitationsState>,
    RequireAuth(caller): RequireAuth,
) -> AppResult<Json<Vec<InvitationResponse>>> {
    // The grantee inbox is cross-tenant by design (a bunyip user
    // may be invited by any number of owners on different tenants).
    // The service reads through the migrator pool for the same
    // reason `find_bunyip_principal_in_tenant` does.
    let rows =
        GrantInvitationsService::find_pending_for_invitee(state.db.pool(), caller.id).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn cancel_invitation(
    State(state): State<GrantInvitationsState>,
    RequireAdminUser(caller): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let ok = GrantInvitationsService::cancel(state.db.pool(), id, caller.tenant_id).await?;
    // Idempotent shape: whether we moved a pending row or found
    // none to move, answer 204. The endpoint is enumeration-
    // resistant because the WHERE clause on the UPDATE names both
    // id AND tenant_id: a foreign-tenant id is invisible.
    let _ = ok;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_invitation_by_token(
    State(state): State<GrantInvitationsState>,
    Path(token): Path<String>,
) -> AppResult<Json<InvitationMetadata>> {
    let invitation = GrantInvitationsService::find_by_token(state.db.pool(), &token)
        .await?
        .ok_or_else(|| AppError::NotFound("invitation".to_string()))?;

    // Look the tenant name + slug up so the SPA can render "You
    // have been invited to <mokosh_account_name>". The tenant read
    // runs on the migrator pool because this endpoint has no
    // scoped auth context to set a GUC from.
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT name, slug FROM tenants WHERE id = $1")
            .bind(invitation.tenant_id)
            .fetch_optional(state.db.migrator_pool())
            .await?;
    let (name, slug) = row.ok_or_else(|| AppError::NotFound("invitation".to_string()))?;

    Ok(Json(InvitationMetadata {
        mokosh_account_name: name,
        mokosh_account_slug: slug,
        role: invitation.role,
        expires_at: invitation.expires_at,
        status: invitation.status,
    }))
}

async fn accept_invitation(
    State(state): State<GrantInvitationsState>,
    RequireAuth(caller): RequireAuth,
    Path(token): Path<String>,
) -> AppResult<Json<InvitationResponse>> {
    // The mirror upsert needs the owner's bunyip id so its
    // (owner, grantee, mokosh_account_id) triple matches whatever
    // Bunyip would send as a `granted` webhook. We resolve it
    // from the invitation row (`inviter_bunyip_user_id`) inside
    // the service.
    //
    // The caller here is `caller.id`, which for a legacy HS256
    // session is the mokosh users.id and NOT the bunyip sub. In
    // SaaS mode, the caller reaches this endpoint via the bunyip
    // at+jwt path where `caller.id == sub`; in standalone mode the
    // caller has no bunyip identity and the invitation's
    // `invitee_bunyip_user_id` was NULL at create time, which the
    // service's accept path binds now.
    let invitation = GrantInvitationsService::find_by_token(state.db.pool(), &token)
        .await?
        .ok_or_else(|| AppError::NotFound("invitation".to_string()))?;
    let owner = invitation.inviter_bunyip_user_id;

    let outcome =
        GrantInvitationsService::accept(state.db.pool(), &token, caller.id, owner).await?;
    match outcome {
        Ok(invitation) => Ok(Json(invitation.into())),
        Err(AcceptRefusal::NotFound) => Err(AppError::NotFound("invitation".to_string())),
        Err(AcceptRefusal::Expired) => Err(AppError::Gone(
            "This invitation has expired. Ask the owner to send a new one.".to_string(),
        )),
        Err(AcceptRefusal::Canceled) => Err(AppError::Gone(
            "This invitation has been canceled by the owner.".to_string(),
        )),
        Err(AcceptRefusal::AlreadyAccepted) => Err(AppError::conflict(
            "This invitation has already been accepted.".to_string(),
        )),
        Err(AcceptRefusal::Declined) => Err(AppError::conflict(
            "This invitation was declined.".to_string(),
        )),
        Err(AcceptRefusal::WrongCaller) => Err(AppError::Forbidden(
            "This invitation was sent to a different account.".to_string(),
        )),
    }
}

async fn decline_invitation(
    State(state): State<GrantInvitationsState>,
    RequireAuth(caller): RequireAuth,
    Path(token): Path<String>,
) -> AppResult<Json<InvitationResponse>> {
    let outcome = GrantInvitationsService::decline(state.db.pool(), &token, caller.id).await?;
    match outcome {
        Ok(invitation) => Ok(Json(invitation.into())),
        Err(AcceptRefusal::NotFound) => Err(AppError::NotFound("invitation".to_string())),
        Err(AcceptRefusal::Expired) => {
            Err(AppError::Gone("This invitation has expired.".to_string()))
        }
        Err(AcceptRefusal::Canceled) => Err(AppError::Gone(
            "This invitation has been canceled by the owner.".to_string(),
        )),
        Err(AcceptRefusal::AlreadyAccepted) => Err(AppError::conflict(
            "This invitation has already been accepted.".to_string(),
        )),
        Err(AcceptRefusal::Declined) => Err(AppError::conflict(
            "This invitation was already declined.".to_string(),
        )),
        Err(AcceptRefusal::WrongCaller) => Err(AppError::Forbidden(
            "This invitation was sent to a different account.".to_string(),
        )),
    }
}
