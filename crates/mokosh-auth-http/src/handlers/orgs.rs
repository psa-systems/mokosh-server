//! `/v1/orgs/*` - org-management surface (audit doc 03).
//!
//! Membership-scoped: every endpoint resolves the org by slug, verifies
//! the calling Bearer user is a member, and (for mutations) that they
//! hold `MembershipRole::Owner | Admin`. The 5-state global `UserRole`
//! on the calling user is ignored here: Bunyip platform admins do NOT
//! automatically get to manage every org's members; org-role is the
//! relevant axis.
//!
//! See docs/mokosh-fixes/03-organizations.md.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use mokosh_auth_core::{
    AuditEvent, AuthError, Membership, MembershipRole, MembershipStatus, NewOrgInvitation,
    OrgInvitation, Tenant, TenantId, TenantKind, User, UserId, UserRole,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

const INVITE_TTL_DAYS: i64 = 14;
const MAX_NAME_LEN: usize = 80;
const MAX_SLUG_LEN: usize = 60;

// --- Response shapes ----------------------------------------------------

#[derive(Debug, Serialize)]
pub struct OrgView {
    pub id: String,
    pub slug: String,
    pub name: String,
}

impl From<&Tenant> for OrgView {
    fn from(t: &Tenant) -> Self {
        Self {
            id: t.id.0.to_string(),
            slug: t.slug.clone(),
            name: t.name.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OrgMembershipBriefView {
    pub org: OrgView,
    pub role: MembershipRole,
}

#[derive(Debug, Serialize)]
pub struct MemberUserView {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub lifetime_member: bool,
    pub mfa_enabled: bool,
}

impl From<&User> for MemberUserView {
    fn from(u: &User) -> Self {
        let name = match (u.first_name.as_deref(), u.last_name.as_deref()) {
            (Some(f), Some(l)) => format!("{f} {l}"),
            (Some(f), None) => f.to_string(),
            (None, Some(l)) => l.to_string(),
            _ => u.email.clone(),
        };
        Self {
            id: u.id.0.to_string(),
            email: u.email.clone(),
            name,
            role: u.role,
            email_verified_at: u.email_verified_at,
            lifetime_member: false,
            mfa_enabled: u.mfa_enrolled,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MemberBriefView {
    pub user: MemberUserView,
    pub role: MembershipRole,
}

#[derive(Debug, Serialize)]
pub struct InvitationView {
    pub id: String,
    pub email: String,
    pub role: MembershipRole,
    /// Raw token. Only the issue endpoint returns this; listings echo
    /// the truncated form (the SPA shows a short fingerprint).
    pub token: String,
    pub expires_at: String,
    pub accepted_at: Option<String>,
}

// --- Request shapes -----------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateOrgBody {
    pub name: String,
    #[serde(default)]
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangeRoleBody {
    pub role: MembershipRole,
}

#[derive(Debug, Deserialize)]
pub struct CreateInvitationBody {
    pub email: String,
    pub role: MembershipRole,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AcceptInvitationBody {
    pub token: String,
}

// --- Helpers ------------------------------------------------------------

fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

async fn require_member(
    st: &AuthHttpState,
    user_id: UserId,
    slug: &str,
) -> Result<(Tenant, Membership), HttpError> {
    let tenant = st
        .tenants
        .find_by_slug(slug)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;
    let m = st
        .memberships
        .find(user_id, tenant.id)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;
    if !matches!(m.status, MembershipStatus::Active) {
        return Err(HttpError(AuthError::Forbidden(
            "membership is suspended".into(),
        )));
    }
    Ok((tenant, m))
}

fn require_owner_or_admin(m: &Membership) -> Result<(), HttpError> {
    if !m.org_role.can_manage_members() {
        return Err(HttpError(AuthError::Forbidden(
            "owner or admin role required".into(),
        )));
    }
    Ok(())
}

fn random_token() -> String {
    mokosh_auth_crypto::generate_opaque_token()
}

// --- Handlers -----------------------------------------------------------

/// GET /v1/orgs - list the caller's org memberships (kind='org' only;
/// personal tenants live on the tenant switcher surface).
pub async fn list_my_orgs(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
) -> Result<Json<Vec<OrgMembershipBriefView>>, HttpError> {
    let memberships = st
        .memberships
        .list_for_user(caller.id)
        .await
        .map_err(HttpError)?;

    let mut out = Vec::with_capacity(memberships.len());
    for m in memberships {
        if !matches!(m.status, MembershipStatus::Active) {
            continue;
        }
        let tenant = match st
            .tenants
            .find_by_id(m.tenant_id)
            .await
            .map_err(HttpError)?
        {
            Some(t) => t,
            None => continue,
        };
        if !matches!(tenant.kind, TenantKind::Org) {
            continue;
        }
        out.push(OrgMembershipBriefView {
            org: OrgView::from(&tenant),
            role: m.org_role,
        });
    }
    Ok(Json(out))
}

/// POST /v1/orgs - create a new org. Founder becomes Owner.
pub async fn create_org(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Json(body): Json<CreateOrgBody>,
) -> Result<(StatusCode, Json<OrgView>), HttpError> {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(HttpError(AuthError::InvalidRequest(format!(
            "name: 1-{MAX_NAME_LEN} chars"
        ))));
    }
    let requested_slug = body
        .slug
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| slugify(&name));
    let base_slug = if requested_slug.is_empty() {
        "org".to_string()
    } else {
        requested_slug
    };
    if base_slug.len() > MAX_SLUG_LEN {
        return Err(HttpError(AuthError::InvalidRequest(format!(
            "slug: 1-{MAX_SLUG_LEN} chars"
        ))));
    }

    // Uniqueness suffix on conflict: `acme-corp`, `acme-corp-2`, ...
    let mut slug = base_slug.clone();
    let mut attempt = 1u32;
    let tenant = loop {
        match st
            .tenants
            .create_org(&name, &slug, caller.id, caller.role)
            .await
        {
            Ok(t) => break t,
            Err(AuthError::Conflict(_)) if attempt < 50 => {
                attempt += 1;
                slug = format!("{base_slug}-{attempt}");
            }
            Err(e) => return Err(HttpError(e)),
        }
    };

    let _ = st
        .provider
        .audit
        .record(
            Some(tenant.id),
            Some(caller.id),
            None,
            AuditEvent::AdminAction {
                admin_id: caller.id,
                action: "org.created".into(),
                target: tenant.id.0.to_string(),
            },
        )
        .await;

    Ok((StatusCode::CREATED, Json(OrgView::from(&tenant))))
}

/// GET /v1/orgs/:slug - org detail (members count not included today).
pub async fn get_org(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path(slug): Path<String>,
) -> Result<Json<OrgView>, HttpError> {
    let (tenant, _) = require_member(&st, caller.id, &slug).await?;
    Ok(Json(OrgView::from(&tenant)))
}

/// GET /v1/orgs/:slug/members
pub async fn list_members(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path(slug): Path<String>,
) -> Result<Json<Vec<MemberBriefView>>, HttpError> {
    let (tenant, _) = require_member(&st, caller.id, &slug).await?;
    let memberships = st
        .memberships
        .list_for_tenant(tenant.id)
        .await
        .map_err(HttpError)?;

    let mut out = Vec::with_capacity(memberships.len());
    for m in memberships {
        let user = match st
            .provider
            .users
            .find_by_id(m.user_id)
            .await
            .map_err(HttpError)?
        {
            Some(u) => u,
            None => continue,
        };
        out.push(MemberBriefView {
            user: MemberUserView::from(&user),
            role: m.org_role,
        });
    }
    Ok(Json(out))
}

/// POST /v1/orgs/:slug/members/:user_id/role - change a member's org role.
pub async fn change_member_role(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path((slug, user_id)): Path<(String, uuid::Uuid)>,
    Json(body): Json<ChangeRoleBody>,
) -> Result<Response, HttpError> {
    let (tenant, caller_m) = require_member(&st, caller.id, &slug).await?;
    require_owner_or_admin(&caller_m)?;

    let target_uid = UserId(user_id);
    let target_m = st
        .memberships
        .find(target_uid, tenant.id)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;

    // Last-owner guard: cannot demote the last remaining Owner.
    if matches!(target_m.org_role, MembershipRole::Owner)
        && !matches!(body.role, MembershipRole::Owner)
    {
        let other_owners = st
            .memberships
            .count_owners_excluding(tenant.id, target_uid)
            .await
            .map_err(HttpError)?;
        if other_owners == 0 {
            return Err(HttpError(AuthError::InvalidRequest(
                "cannot demote the last owner of this org".into(),
            )));
        }
    }

    // Only Owners can promote to Owner.
    if matches!(body.role, MembershipRole::Owner)
        && !matches!(caller_m.org_role, MembershipRole::Owner)
    {
        return Err(HttpError(AuthError::Forbidden(
            "only owners can promote to owner".into(),
        )));
    }

    st.memberships
        .change_org_role(target_uid, tenant.id, body.role)
        .await
        .map_err(HttpError)?;

    let _ = st
        .provider
        .audit
        .record(
            Some(tenant.id),
            Some(caller.id),
            None,
            AuditEvent::AdminAction {
                admin_id: caller.id,
                action: format!("org.member_role_changed:{}", body.role.as_str()),
                target: target_uid.0.to_string(),
            },
        )
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// DELETE /v1/orgs/:slug/members/:user_id
pub async fn remove_member(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path((slug, user_id)): Path<(String, uuid::Uuid)>,
) -> Result<Response, HttpError> {
    let (tenant, caller_m) = require_member(&st, caller.id, &slug).await?;
    require_owner_or_admin(&caller_m)?;

    let target_uid = UserId(user_id);
    let target_m = st
        .memberships
        .find(target_uid, tenant.id)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;

    // Last-owner guard.
    if matches!(target_m.org_role, MembershipRole::Owner) {
        let other_owners = st
            .memberships
            .count_owners_excluding(tenant.id, target_uid)
            .await
            .map_err(HttpError)?;
        if other_owners == 0 {
            return Err(HttpError(AuthError::InvalidRequest(
                "cannot remove the last owner of this org".into(),
            )));
        }
    }

    st.memberships
        .delete(target_uid, tenant.id)
        .await
        .map_err(HttpError)?;

    let _ = st
        .provider
        .audit
        .record(
            Some(tenant.id),
            Some(caller.id),
            None,
            AuditEvent::AdminAction {
                admin_id: caller.id,
                action: "org.member_removed".into(),
                target: target_uid.0.to_string(),
            },
        )
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /v1/orgs/:slug/invitations - list open invitations.
pub async fn list_invitations(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path(slug): Path<String>,
) -> Result<Json<Vec<InvitationView>>, HttpError> {
    let (tenant, caller_m) = require_member(&st, caller.id, &slug).await?;
    require_owner_or_admin(&caller_m)?;

    let invites = st
        .org_invitations
        .list_open_for_tenant(tenant.id)
        .await
        .map_err(HttpError)?;

    // Listings echo the database id as the token affordance (the raw
    // token is opaque-hashed at rest; the SPA only needs a short
    // identifier per row). The issue endpoint is the only place that
    // returns the raw token to the inviter.
    let out: Vec<InvitationView> = invites
        .into_iter()
        .map(|i| InvitationView {
            id: i.id.to_string(),
            email: i.email,
            role: i.org_role,
            token: format!("{}", i.id), // opaque to the SPA listing
            expires_at: i.expires_at.to_rfc3339(),
            accepted_at: i.accepted_at.map(|t| t.to_rfc3339()),
        })
        .collect();
    Ok(Json(out))
}

/// POST /v1/orgs/:slug/invitations - issue a fresh invite.
pub async fn create_invitation(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path(slug): Path<String>,
    Json(body): Json<CreateInvitationBody>,
) -> Result<(StatusCode, Json<InvitationView>), HttpError> {
    let (tenant, caller_m) = require_member(&st, caller.id, &slug).await?;
    require_owner_or_admin(&caller_m)?;

    let email = body.email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(HttpError(AuthError::InvalidRequest(
            "email: required".into(),
        )));
    }

    // Owner promotion is owner-only.
    if matches!(body.role, MembershipRole::Owner)
        && !matches!(caller_m.org_role, MembershipRole::Owner)
    {
        return Err(HttpError(AuthError::Forbidden(
            "only owners can invite owners".into(),
        )));
    }

    let raw_token = random_token();
    let invite = st
        .org_invitations
        .issue(NewOrgInvitation {
            tenant_id: tenant.id,
            email: email.clone(),
            org_role: body.role,
            token: raw_token.clone(),
            invited_by: caller.id,
            expires_at: Utc::now() + Duration::days(INVITE_TTL_DAYS),
            note: body.note,
        })
        .await
        .map_err(HttpError)?;

    let _ = st
        .provider
        .audit
        .record(
            Some(tenant.id),
            Some(caller.id),
            None,
            AuditEvent::AdminAction {
                admin_id: caller.id,
                action: "org.invite_issued".into(),
                target: invite.id.to_string(),
            },
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(InvitationView {
            id: invite.id.to_string(),
            email: invite.email,
            role: invite.org_role,
            token: raw_token,
            expires_at: invite.expires_at.to_rfc3339(),
            accepted_at: None,
        }),
    ))
}

/// DELETE /v1/orgs/:slug/invitations/:id - revoke an open invite.
pub async fn revoke_invitation(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path((slug, invite_id)): Path<(String, uuid::Uuid)>,
) -> Result<Response, HttpError> {
    let (tenant, caller_m) = require_member(&st, caller.id, &slug).await?;
    require_owner_or_admin(&caller_m)?;

    st.org_invitations
        .revoke(invite_id, caller.id)
        .await
        .map_err(HttpError)?;

    let _ = st
        .provider
        .audit
        .record(
            Some(tenant.id),
            Some(caller.id),
            None,
            AuditEvent::AdminAction {
                admin_id: caller.id,
                action: "org.invite_revoked".into(),
                target: invite_id.to_string(),
            },
        )
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// --- Cross-org invite accept (bound to a signed-in user) ---------------

/// POST /v1/invitations/accept - accept an invitation by raw token.
/// The caller must be signed in (Bearer token); the invitation's email
/// is informational, not enforced against the caller's identity (the
/// SPA already shows the recipient who is accepting).
pub async fn accept_invitation(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Json(body): Json<AcceptInvitationBody>,
) -> Result<Json<OrgView>, HttpError> {
    let token_hash = mokosh_auth_crypto::hash_opaque_token(&body.token);
    let invite: OrgInvitation = st
        .org_invitations
        .accept(token_hash, caller.id, caller.role)
        .await
        .map_err(HttpError)?;
    let tenant = st
        .tenants
        .find_by_id(invite.tenant_id)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;

    let _ = st
        .provider
        .audit
        .record(
            Some(tenant.id),
            Some(caller.id),
            None,
            AuditEvent::AdminAction {
                admin_id: caller.id,
                action: "org.invite_accepted".into(),
                target: invite.id.to_string(),
            },
        )
        .await;

    Ok(Json(OrgView::from(&tenant)))
}

#[derive(Debug, Serialize)]
pub struct InvitationLookupView {
    pub email: String,
    pub role: MembershipRole,
    pub org: OrgView,
    pub inviter_name: Option<String>,
    pub expired: bool,
}

#[derive(Debug, Deserialize)]
pub struct LookupQuery {
    pub token: String,
}

/// GET /v1/invitations/lookup?token=... - preview an invite without
/// accepting. Used by the SPA's invite-accept page to render "You are
/// being invited to <Org>".
pub async fn lookup_invitation(
    State(st): State<Arc<AuthHttpState>>,
    axum::extract::Query(q): axum::extract::Query<LookupQuery>,
) -> Result<Json<InvitationLookupView>, HttpError> {
    let token_hash = mokosh_auth_crypto::hash_opaque_token(&q.token);
    let invite = st
        .org_invitations
        .find_by_token_hash(token_hash)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;
    if invite.accepted_at.is_some() || invite.revoked_at.is_some() {
        return Err(HttpError(AuthError::NotFound));
    }
    let tenant = st
        .tenants
        .find_by_id(invite.tenant_id)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;
    let inviter_name = st
        .provider
        .users
        .find_by_id(invite.invited_by)
        .await
        .map_err(HttpError)?
        .map(
            |u| match (u.first_name.as_deref(), u.last_name.as_deref()) {
                (Some(f), Some(l)) => format!("{f} {l}"),
                (Some(f), None) => f.to_string(),
                (None, Some(l)) => l.to_string(),
                _ => u.email,
            },
        );
    let expired = invite.expires_at < Utc::now();
    Ok(Json(InvitationLookupView {
        email: invite.email,
        role: invite.org_role,
        org: OrgView::from(&tenant),
        inviter_name,
        expired,
    }))
}

// --- Optional leave -----------------------------------------------------

/// POST /v1/orgs/:slug/leave - the caller voluntarily removes themself.
/// Refuses if they are the last Owner.
pub async fn leave_org(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path(slug): Path<String>,
) -> Result<Response, HttpError> {
    let (tenant, m) = require_member(&st, caller.id, &slug).await?;
    if matches!(m.org_role, MembershipRole::Owner) {
        let others = st
            .memberships
            .count_owners_excluding(tenant.id, caller.id)
            .await
            .map_err(HttpError)?;
        if others == 0 {
            return Err(HttpError(AuthError::InvalidRequest(
                "cannot leave: you are the last owner".into(),
            )));
        }
    }
    st.memberships
        .delete(caller.id, tenant.id)
        .await
        .map_err(HttpError)?;
    let _ = st
        .provider
        .audit
        .record(
            Some(tenant.id),
            Some(caller.id),
            None,
            AuditEvent::AdminAction {
                admin_id: caller.id,
                action: "org.member_left".into(),
                target: caller.id.0.to_string(),
            },
        )
        .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}
