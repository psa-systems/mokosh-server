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

use super::bunyip_directory::BunyipUserDirectory;
use super::grant_invitations::{
    AcceptRefusal, CreatedInvitation, GrantInvitation, GrantInvitationsService, DEFAULT_TTL,
};
use super::middleware::{RequireAdminUser, RequireAuth};
use super::tenant::TenantId;
use crate::db::Database;
use crate::modules::notifications::NotificationsService;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct GrantInvitationsState {
    pub db: Arc<Database>,
    /// The mokosh-apps origin; the invitation email's accept link is
    /// `{spa_base_url}/accept-grant?token=<plaintext>`. In SaaS mode
    /// this is the tenant's mokosh SPA origin; in standalone mode it
    /// is the deployment's single spa host.
    pub spa_base_url: Arc<String>,
    /// Dispatch queue for the invitation email. `None` in tests that
    /// do not wire notifications; the create handler still succeeds
    /// and logs at warn so a fixture without notifications does not
    /// silently swallow the email.
    pub notifications: Option<Arc<NotificationsService>>,
    /// PMS-1208: Bunyip user-directory client for the SaaS-mode gate.
    /// `Some` when this deployment federates with Bunyip AND the
    /// three `BUNYIP_DIRECTORY_*` config values are all set; `None`
    /// in standalone mode. When `Some` the create handler refuses
    /// an invitation to an email that does not resolve on Bunyip
    /// with a 422 pointing the owner at "ask them to sign up first";
    /// when `None` the standalone accept-time flow binds a local
    /// `users.id` at accept time and the pre-check is skipped.
    pub bunyip_directory: Option<Arc<BunyipUserDirectory>>,
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
pub fn grant_invitations_owner_routes(
    db: Arc<Database>,
    spa_base_url: Arc<String>,
    notifications: Option<Arc<NotificationsService>>,
    bunyip_directory: Option<Arc<BunyipUserDirectory>>,
) -> Router {
    let state = GrantInvitationsState {
        db,
        spa_base_url,
        notifications,
        bunyip_directory,
    };
    Router::new()
        .route("/", post(create_invitation))
        .route("/", get(list_owner_outbox))
        .route("/{id}", delete(cancel_invitation))
        .with_state(state)
}

/// Grantee-facing mount. Sits under `/api/v1/my-grants/invitations`.
///
/// The id-scoped accept/decline routes live here alongside the inbox
/// read: the caller is already authenticated as the grantee, the id
/// comes from THEIR own inbox row, and the service's `accept_by_id` /
/// `decline_by_id` refuse anything not addressed to `caller.id`. The
/// SPA switcher never sees the plaintext token (that lives only in
/// the invitation email); before this the switcher was posting the
/// invitation id to the by-token endpoint and every accept returned
/// 404 "invitation not found".
///
/// `bunyip_directory` is threaded through so the SaaS-mode accept
/// path can register the grant on bunyip inside `accept_by_id` (same
/// contract the by-token mount enforces at line 193 comments).
pub fn grant_invitations_grantee_routes(
    db: Arc<Database>,
    bunyip_directory: Option<Arc<BunyipUserDirectory>>,
) -> Router {
    let state = GrantInvitationsState {
        db,
        spa_base_url: Arc::new(String::new()),
        notifications: None,
        bunyip_directory,
    };
    Router::new()
        .route("/", get(list_grantee_inbox))
        .route("/{id}/accept", post(accept_by_id_handler))
        .route("/{id}/decline", post(decline_by_id_handler))
        .with_state(state)
}

/// Unauthenticated mount for the token-driven endpoints. Sits
/// under `/api/v1/grants/invitations/by-token`.
///
/// `bunyip_directory` is REQUIRED positional, not an Option with a
/// default and not a builder method, even though its own type stays
/// `Option<...>` because `None` legitimately means standalone mode.
/// The property being enforced in source is that a mount cannot
/// forget to decide: a `None` default here silently skipped the
/// bunyip grant registration in SaaS mode for every accept between
/// PMS-1208 landing and this fix, because `accept_invitation`
/// receives the state from this mount and passes its
/// `bunyip_directory` on to `GrantInvitationsService::accept` (see
/// the "finding 5" block in `grant_invitations.rs`). The register
/// block was already correct - the handle it needed was thrown away
/// two callers up, in this constructor. Making the parameter
/// positional means a future mount fails to compile rather than
/// repeating the same silent skip.
pub fn grant_invitations_by_token_routes(
    db: Arc<Database>,
    bunyip_directory: Option<Arc<BunyipUserDirectory>>,
) -> Router {
    let state = GrantInvitationsState {
        db,
        spa_base_url: Arc::new(String::new()),
        notifications: None,
        bunyip_directory,
    };
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
    // PMS-1208 SaaS-mode gate: in the bunyip-federated deployment
    // (`bunyip_directory` is `Some`) the grantee eventually signs in
    // through Bunyip and the accept flow binds their Bunyip sub, so
    // an invitation to an email that does not resolve on Bunyip is
    // a dead end. Refuse it here with 422 pointing the owner at
    // "ask them to sign up first" rather than reaching that dead
    // end at accept time. In standalone mode (`None`) the accept
    // flow binds a local `users.id` and no external identity
    // exists to check against, so this gate is skipped and the
    // invitation goes through email-only. When the request already
    // carries `invitee_bunyip_user_id` a directory hit is
    // guaranteed by construction, so the gate is only invoked on
    // the email path.
    //
    // PMS-1208 finding 7: a hit whose `email_verified` is false is
    // ALSO refused, because BUNYIP-674 option B's grantee JIT gate
    // refuses to place an unverified identity into someone else's
    // tenant (deliberate: the placeholder path exists only for
    // first-sight owners bunyip is in the middle of verifying, and
    // an unverified identity is not one worth placing in someone
    // else's tenant). Without this second half the owner sends the
    // mail, the grantee accepts, and the switch dead-ends at the
    // generic 403 the middleware answers with. Refusing the
    // invitation gives the owner the message they can ACT on.
    let invitee_id_from_directory: Option<Uuid> = match (
        &state.bunyip_directory,
        body.invitee_bunyip_user_id,
        invitee_email,
    ) {
        (Some(directory), None, Some(em)) => match directory.lookup(em).await? {
            Some(hit) if hit.email_verified => Some(hit.user_id),
            Some(_) => {
                return Err(AppError::validation_field(
                    "invitee_email",
                    "This person is registered on Bunyip but has not verified their email address \
                     yet. Ask them to verify their email, then send the invitation.",
                ));
            }
            None => {
                return Err(AppError::validation_field(
                    "invitee_email",
                    "This email is not registered on Bunyip yet. Ask them to sign up first, \
                     then send the invitation.",
                ));
            }
        },
        _ => None,
    };

    // The service's create returns Conflict on the partial-UNIQUE
    // trip; the "already an active grant" pre-check runs here so
    // the two 409s are named separately.
    let addr = invitee_email
        .map(str::to_string)
        .unwrap_or_else(|| body.invitee_bunyip_user_id.unwrap().to_string());
    let resolved_invitee_id = body.invitee_bunyip_user_id.or(invitee_id_from_directory);
    let CreatedInvitation {
        invitation,
        accept_token,
        // SAFETY (PMS-285): no RLS on `mokosh_grant_invitations`; the
        // INSERT names `tenant_id` from the authenticated caller.
    } = GrantInvitationsService::create(
        state.db.pool(),
        caller.tenant_id,
        caller.id,
        resolved_invitee_id,
        &addr,
        body.role.trim(),
        DEFAULT_TTL,
    )
    .await?;

    // Fire the invitation email through the notifications
    // dispatcher (`auth.mokosh_grant_invite` template, migration 223).
    // Best-effort: a mailer failure warns but does NOT roll back the
    // invitation row, because the owner can resend from the outbox and
    // the created row is still cancelable / accepatable through the
    // token they can also copy-paste in dev. Skipping is loud, not
    // silent.
    match state.notifications.as_ref() {
        Some(notify) => {
            let accept_url = format!(
                "{}/accept-grant?token={}",
                state.spa_base_url.trim_end_matches('/'),
                accept_token
            );
            let context = serde_json::json!({
                "recipient_email": invitation.invitee_email,
                "invitee_display_name": local_part(&invitation.invitee_email),
                "inviter_display_name": display_name_for(&caller),
                "mokosh_account_name": lookup_tenant_name(&state, caller.tenant_id)
                    .await
                    .unwrap_or_default(),
                "role_display": role_display(&invitation.role),
                "accept_url": accept_url,
                "expires_at_human": humanize_expiry(invitation.expires_at),
            });
            if let Err(e) = notify
                .dispatch(
                    TenantId::from_trusted(caller.tenant_id),
                    "auth.mokosh_grant_invite",
                    &context,
                )
                .await
            {
                tracing::warn!(
                    invitation_id = %invitation.id,
                    error = ?e,
                    "grant invitation notify dispatch failed; row persisted, owner can resend"
                );
            } else {
                tracing::info!(
                    invitation_id = %invitation.id,
                    "grant invitation email queued via notifications dispatcher"
                );
            }
        }
        None => tracing::warn!(
            invitation_id = %invitation.id,
            "no notifications dispatcher wired; grant invitation persisted but no email queued"
        ),
    }

    Ok((
        StatusCode::CREATED,
        Json(CreatedInvitationResponse {
            invitation: invitation.into(),
            accept_token,
        }),
    ))
}

/// Local part of an email address, for a plausible display name
/// when userinfo has not been consulted (or is not available in
/// standalone mode). `"alice@example.com"` -> `"alice"`; a value
/// with no `@` is returned as-is.
fn local_part(email: &str) -> String {
    email
        .split_once('@')
        .map(|(local, _)| local)
        .unwrap_or(email)
        .to_string()
}

/// Best-effort display name for the inviter, matching the shape
/// `auth.welcome` uses: `first_name last_name` when both are
/// present, else whichever is set, else the email local part.
fn display_name_for(caller: &super::CurrentUser) -> String {
    let f = caller.first_name.trim();
    let l = caller.last_name.trim();
    match (f, l) {
        ("", "") => local_part(&caller.email),
        (f, "") => f.to_string(),
        ("", l) => l.to_string(),
        (f, l) => format!("{f} {l}"),
    }
}

/// Title-cased human label for the PMS-1162 role vocab.
fn role_display(role: &str) -> String {
    match role {
        "admin" => "Admin".to_string(),
        "manager" => "Manager".to_string(),
        "technician" => "Technician".to_string(),
        "finance" => "Finance".to_string(),
        "read_only" => "Read only".to_string(),
        other => other.to_string(),
    }
}

/// "in 7 days" for a 7-day-out expiry, an absolute date otherwise.
/// Deliberately coarse: the template says "the invitation expires
/// {{expires_at_human}}", and a to-the-minute label reads worse than
/// a rounded one.
fn humanize_expiry(expires_at: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let days = (expires_at - now).num_days();
    if (1..=14).contains(&days) {
        format!("in {days} days")
    } else {
        expires_at.format("on %B %-d, %Y").to_string()
    }
}

/// Look the account name up for the `mokosh_account_name` template
/// key. Errors and missing rows read as empty string so the email
/// still fires with the substitution blank rather than blocking on
/// a name lookup.
async fn lookup_tenant_name(state: &GrantInvitationsState, tenant_id: Uuid) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT name FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(state.db.migrator_pool())
        .await
        .ok()
        .flatten()
        .map(|(name,)| name)
}

async fn list_owner_outbox(
    State(state): State<GrantInvitationsState>,
    RequireAdminUser(caller): RequireAdminUser,
) -> AppResult<Json<Vec<InvitationResponse>>> {
    // SAFETY (PMS-285): `mokosh_grant_invitations` has no RLS policy;
    // the service query filters on `tenant_id = $1` with the caller's
    // authenticated tenant.
    let rows =
        GrantInvitationsService::find_pending_by_tenant(state.db.pool(), caller.tenant_id).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn list_grantee_inbox(
    State(state): State<GrantInvitationsState>,
    RequireAuth(caller): RequireAuth,
) -> AppResult<Json<Vec<InvitationResponse>>> {
    // SAFETY (PMS-285): the grantee inbox is cross-tenant by design
    // (a bunyip user may be invited by any number of owners on
    // different tenants); no `tenant_id` scope makes sense here.
    // `mokosh_grant_invitations` has no RLS policy and the read filters
    // on `invitee_bunyip_user_id = $1` with the caller's own sub.
    let rows =
        GrantInvitationsService::find_pending_for_invitee(state.db.pool(), caller.id).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn cancel_invitation(
    State(state): State<GrantInvitationsState>,
    RequireAdminUser(caller): RequireAdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    // SAFETY (PMS-285): no RLS on `mokosh_grant_invitations`; the
    // UPDATE names BOTH `id` AND `tenant_id`, so a foreign-tenant id
    // is invisible (enumeration-resistant).
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
    // SAFETY (PMS-285): this is a pre-auth path - the token in the
    // URL IS the credential (Argon2 hash on the row, single-use). No
    // `tenant_id` scope is available yet and none is needed: the
    // token uniquely identifies the row.
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
    // SAFETY (PMS-285): pre-auth-ish path (the caller is authenticated
    // via `RequireAuth` but on the GRANTEE plane, not the tenant plane;
    // there is no owner-tenant scope to set here). The token in the URL
    // uniquely identifies the row, and the WRITE half checks
    // `invitee_bunyip_user_id` against `caller.id` inside the service
    // (`WrongCaller` refusal).
    let invitation = GrantInvitationsService::find_by_token(state.db.pool(), &token)
        .await?
        .ok_or_else(|| AppError::NotFound("invitation".to_string()))?;
    let owner = invitation.inviter_bunyip_user_id;

    // SAFETY (PMS-285): same shape as the read above. `accept` runs
    // its own guarded UPDATE (WHERE id = ... AND status = 'pending')
    // and calls the mirror upsert on `mokosh_bunyip_grants`, which
    // also has no RLS.
    let outcome = GrantInvitationsService::accept(
        state.db.pool(),
        &token,
        caller.id,
        owner,
        state.bunyip_directory.as_deref(),
    )
    .await?;
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

/// Grantee-scoped accept by invitation id, mounted at
/// `POST /api/v1/my-grants/invitations/{id}/accept`. The SPA switcher
/// posts the id it read from the grantee inbox
/// (`GET /my-grants/invitations`), which never carries a plaintext
/// token; the service layer's `accept_by_id` enforces the strict
/// invitee-vs-caller match and reuses the same guarded UPDATE + mirror
/// upsert as the by-token path.
async fn accept_by_id_handler(
    State(state): State<GrantInvitationsState>,
    RequireAuth(caller): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<InvitationResponse>> {
    // SAFETY (PMS-285): grantee-plane path, no owner-tenant scope
    // available here. `accept_by_id` re-reads by id and gates on
    // (invitee_bunyip_user_id = caller.id) before any write, so a
    // foreign id 404s (well, WrongCaller-Forbidden's) rather than
    // leaking a row.
    let outcome = GrantInvitationsService::accept_by_id(
        state.db.pool(),
        id,
        caller.id,
        state.bunyip_directory.as_deref(),
    )
    .await?;
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

/// Grantee-scoped decline by invitation id. Same shape as
/// [`accept_by_id_handler`] minus the bunyip register and mirror
/// upsert.
async fn decline_by_id_handler(
    State(state): State<GrantInvitationsState>,
    RequireAuth(caller): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<InvitationResponse>> {
    // SAFETY (PMS-285): same shape as `accept_by_id_handler`.
    let outcome = GrantInvitationsService::decline_by_id(state.db.pool(), id, caller.id).await?;
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

async fn decline_invitation(
    State(state): State<GrantInvitationsState>,
    RequireAuth(caller): RequireAuth,
    Path(token): Path<String>,
) -> AppResult<Json<InvitationResponse>> {
    // SAFETY (PMS-285): mirrors the accept path above - token
    // uniquely identifies the row, no RLS on the table, and the
    // guarded UPDATE stays enumeration-resistant.
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

#[cfg(test)]
mod wiring_guards {
    //! Regression guards for the bunyip-directory wiring on the
    //! by-token mount. Written as source scans because the failure
    //! mode being pinned is exactly a compile-time choice that
    //! silently produces the wrong runtime behaviour: an ordinary
    //! service-level test of `GrantInvitationsService::accept` passes
    //! without the mount ever handing the directory through, which is
    //! how the defect shipped in the first place.
    //!
    //! The property being enforced is that a caller of
    //! `grant_invitations_by_token_routes` must decide whether to
    //! wire a directory or not; a `None` default is what let the
    //! router forget to decide. A future mount then fails to compile
    //! rather than silently skipping registration.

    /// The by-token constructor must take a `bunyip_directory`
    /// argument positionally and consume it into the state, not
    /// hard-code `None`.
    #[test]
    fn by_token_constructor_consumes_its_directory_argument() {
        let src = include_str!("grant_invitations_routes.rs");
        let start = src
            .find("pub fn grant_invitations_by_token_routes(")
            .expect("by-token constructor present");
        // Body ends at the next top-level `pub fn` or `async fn`.
        let tail = &src[start..];
        let end = tail
            .find("\npub fn ")
            .or_else(|| tail.find("\nasync fn "))
            .unwrap_or(tail.len());
        let body = &tail[..end];

        assert!(
            body.contains("bunyip_directory: Option<Arc<BunyipUserDirectory>>"),
            "the by-token constructor must take `bunyip_directory` positionally so a \
             mount cannot forget to decide whether to wire it: {body}"
        );
        assert!(
            !body.contains("bunyip_directory: None"),
            "the by-token constructor must not hard-code `bunyip_directory: None` \
             (regression: the accept flow silently skipped bunyip grant \
             registration in SaaS mode for every accept until this was fixed): {body}"
        );
        assert!(
            body.contains("bunyip_directory,"),
            "the by-token constructor must move its `bunyip_directory` argument into \
             the state so `accept_invitation` receives it: {body}"
        );
    }

    /// The `create_api_router` mount that hands to
    /// `grant_invitations_by_token_routes` must forward
    /// `bunyip_directory` into the constructor. Anchors on the
    /// constructor call itself (a bare `nest(` on the URL matches
    /// nearby doc-comments too, which is why we anchor on the fn
    /// call).
    #[test]
    fn create_api_router_passes_directory_to_the_by_token_mount() {
        let src = include_str!("../../api/router.rs");
        let anchor = "grant_invitations_by_token_routes(";
        let idx = src
            .find(anchor)
            .expect("by-token constructor call present in create_api_router");
        // Search a bounded window from the call site for the argument
        // list. 400 bytes is enough for a multi-line call with heavy
        // whitespace.
        let window = &src[idx..idx.saturating_add(400).min(src.len())];
        assert!(
            window.contains("bunyip_directory"),
            "the by-token constructor call in create_api_router must forward \
             bunyip_directory (regression: without this the constructor receives \
             the default and silently skips grant registration): {window}"
        );
    }
}
