//! MAPPS-875: owner-side grant management surface.
//!
//! The tenant owner sees two lists on their `/settings/sharing` page:
//! - PENDING invitations (from `mokosh_grant_invitations`, PMS-1208).
//!   Cancel goes through the existing `DELETE /grants/invitations/{id}`.
//! - ACTIVE grants (bunyip's `mokosh_account_grants` in SaaS mode,
//!   mokosh's mirror in standalone). Revoke goes through the new
//!   `DELETE /grants/{id}` here, which fans out to bunyip in SaaS or
//!   the local mirror in standalone.
//!
//! Two routes today:
//! - `GET  /grants?role=owner` -> `{ pending, active }`
//! - `DELETE /grants/{id}` -> 204 revoked
//!
//! Both mount at `/api/v1/grants` and both take `RequireAdminUser`
//! (only the owner-admin of a tenant may share it). In SaaS mode the
//! active-grants read AND the revoke call fan out through
//! `BunyipUserDirectory` (MAPPS-875 methods added there) so bunyip's
//! authoritative table remains the source of truth. In standalone
//! mode there is no bunyip and the local mirror is authoritative;
//! both operations read/write `mokosh_bunyip_grants` directly.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use super::bunyip_directory::BunyipUserDirectory;
use super::grant_invitations::GrantInvitationsService;
use super::middleware::RequireAdminUser;
use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct OwnerGrantsState {
    pub db: Arc<Database>,
    /// `Some` in SaaS mode. When `None`, this mount reads and writes
    /// the local mirror as the authoritative source (standalone mode).
    pub bunyip_directory: Option<Arc<BunyipUserDirectory>>,
}

/// Wire shape of `GET /grants?role=owner`. Two lists in one payload:
/// pending invitations and active grants. Every field is required on
/// the wire; missing values default at the read site rather than in
/// serde so the SPA sees a stable shape.
#[derive(Debug, Serialize)]
pub struct OwnerOutbox {
    pub pending: Vec<PendingInvitationView>,
    pub active: Vec<ActiveGrantView>,
}

#[derive(Debug, Serialize)]
pub struct PendingInvitationView {
    pub id: Uuid,
    pub invitee_email: String,
    pub role: String,
    pub invited_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ActiveGrantView {
    /// The uuid mokosh AND bunyip use for the same grant (PMS-1208
    /// finding 4). The SPA sends this to `DELETE /grants/{id}`.
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grantee_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grantee_name: Option<String>,
    pub role: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Reserved for a future `role=grantee` axis; today the endpoint
    /// answers only the owner outbox so an unknown value is a 400
    /// rather than a silent fallback.
    #[serde(default)]
    pub role: Option<String>,
}

/// Mount under `/api/v1/grants` in `create_api_router`.
pub fn owner_grants_routes(
    db: Arc<Database>,
    bunyip_directory: Option<Arc<BunyipUserDirectory>>,
) -> Router {
    let state = OwnerGrantsState {
        db,
        bunyip_directory,
    };
    Router::new()
        .route("/", get(list_owner_outbox))
        .route("/{id}", delete(revoke_owner_grant))
        .with_state(state)
}

async fn list_owner_outbox(
    State(state): State<OwnerGrantsState>,
    RequireAdminUser(caller): RequireAdminUser,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<OwnerOutbox>> {
    let role = query.role.as_deref().unwrap_or("owner");
    if role != "owner" {
        return Err(AppError::BadRequest(format!(
            "unsupported role filter: {role} (only 'owner' is served today)"
        )));
    }

    let pending = pending_for_owner(&state, caller.tenant_id).await?;
    let active = active_for_owner(&state, caller.id).await?;

    Ok(Json(OwnerOutbox { pending, active }))
}

async fn pending_for_owner(
    state: &OwnerGrantsState,
    tenant_id: Uuid,
) -> AppResult<Vec<PendingInvitationView>> {
    let rows = GrantInvitationsService::find_pending_by_tenant(state.db.pool(), tenant_id).await?;
    Ok(rows
        .into_iter()
        .map(|inv| PendingInvitationView {
            id: inv.id,
            invitee_email: inv.invitee_email,
            role: inv.role,
            invited_at: inv.invited_at,
            expires_at: inv.expires_at,
        })
        .collect())
}

async fn active_for_owner(
    state: &OwnerGrantsState,
    owner_bunyip_user_id: Uuid,
) -> AppResult<Vec<ActiveGrantView>> {
    // SaaS mode: bunyip's `mokosh_account_grants` is the source of
    // truth (mokosh's mirror is derived from bunyip's webhooks, so a
    // just-revoked grant reaches bunyip before it reaches the mirror).
    // Standalone mode: no bunyip, the local mirror is authoritative
    // and there is no other reader.
    if let Some(directory) = state.bunyip_directory.as_ref() {
        let grants = directory.list_owner_grants(owner_bunyip_user_id).await?;
        return Ok(grants
            .into_iter()
            .map(|g| ActiveGrantView {
                id: g.grant_id,
                // MAPPS-875 v1 wire shape: grantee_email / grantee_name
                // are shown in the SPA. Bunyip's list does not expose
                // them today; a follow-up call to the directory would
                // add a second round-trip. Deferred: v1 lists by role
                // + granted_at and lets the owner recognise the row by
                // "who did I recently invite" (the email is on the
                // pending row and stays there until accepted). If the
                // UX asks for it, `list_owner_grants` grows the field
                // rather than growing a second call.
                grantee_email: None,
                grantee_name: None,
                role: g.role,
                granted_at: g.granted_at,
            })
            .collect());
    }

    // Standalone: read the mirror. `mokosh_bunyip_grants.grantee_email`
    // is set by PMS-1208 finding 3 (accept-time), so standalone rows
    // carry the email even though bunyip's authoritative table does
    // not.
    let rows = sqlx::query(
        r#"
        SELECT id, bunyip_grant_id, grantee_email, role, granted_at
        FROM mokosh_bunyip_grants
        WHERE owner_bunyip_user_id = $1
          AND revoked_at IS NULL
          AND role IS NOT NULL
        ORDER BY granted_at ASC
        "#,
    )
    .bind(owner_bunyip_user_id)
    .fetch_all(state.db.migrator_pool())
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            // `bunyip_grant_id` is the shared uuid the SPA will send
            // back to `DELETE /grants/{id}` (PMS-1208 finding 4).
            // Falls back to mokosh's mirror `id` when the mirror was
            // created before that column existed on the wire.
            let id = row
                .try_get::<Option<Uuid>, _>("bunyip_grant_id")
                .ok()
                .flatten()
                .unwrap_or_else(|| row.get::<Uuid, _>("id"));
            ActiveGrantView {
                id,
                grantee_email: row
                    .try_get::<Option<String>, _>("grantee_email")
                    .ok()
                    .flatten(),
                grantee_name: None,
                role: row.get::<String, _>("role"),
                granted_at: row.get::<chrono::DateTime<chrono::Utc>, _>("granted_at"),
            }
        })
        .collect())
}

async fn revoke_owner_grant(
    State(state): State<OwnerGrantsState>,
    RequireAdminUser(caller): RequireAdminUser,
    Path(grant_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    if let Some(directory) = state.bunyip_directory.as_ref() {
        // SaaS mode: the machine-authed DELETE on bunyip is the write.
        // Bunyip's revoke:
        // - Refuses foreign-caller / unknown-id with 404 (mokosh
        //   surfaces the same 404 back to the SPA).
        // - Is idempotent on a re-fire.
        // - Fires the webhook, so mokosh's mirror flips within the
        //   30-second stale window without any explicit write here.
        directory.revoke_grant(grant_id, caller.id).await?;
        return Ok(StatusCode::NO_CONTENT);
    }

    // Standalone mode: no bunyip. Write the mirror directly through
    // the existing grantee-leave shape (same UPDATE, different actor
    // tag).
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, mokosh_account_id \
         FROM mokosh_bunyip_grants \
         WHERE (bunyip_grant_id = $1 OR id = $1) \
           AND owner_bunyip_user_id = $2 \
           AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .bind(caller.id)
    .fetch_optional(state.db.migrator_pool())
    .await?;

    let Some((_, mokosh_account_id)) = row else {
        return Err(AppError::NotFound("grant".to_string()));
    };

    // One statement to mark revoked; stamp `revoked_by = 'owner'` so
    // the mokosh audit log can distinguish the two initiators
    // (grantee via `DELETE /my-grants/{id}` stamps `'grantee'`).
    sqlx::query(
        "UPDATE mokosh_bunyip_grants \
         SET revoked_at = NOW(), \
             revoked_by = 'owner', \
             role = NULL, \
             updated_at = NOW() \
         WHERE (bunyip_grant_id = $1 OR id = $1) \
           AND owner_bunyip_user_id = $2 \
           AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .bind(caller.id)
    .execute(state.db.migrator_pool())
    .await?;

    // Belt-and-braces tombstone on the placement row, mirroring the
    // grantee-side leave endpoint. A failure here is a warn.
    if let Err(e) = sqlx::query(
        "UPDATE users SET deleted_at = COALESCE(deleted_at, NOW()), updated_at = NOW() \
         WHERE tenant_id = (SELECT id FROM tenants WHERE slug = $1) \
           AND bunyip_user_id IN ( \
               SELECT grantee_bunyip_user_id FROM mokosh_bunyip_grants \
               WHERE (bunyip_grant_id = $2 OR id = $2) \
           )",
    )
    .bind(&mokosh_account_id)
    .bind(grant_id)
    .execute(state.db.migrator_pool())
    .await
    {
        tracing::warn!(
            error = %e,
            grant_id = %grant_id,
            owner = %caller.id,
            mokosh_account_id = %mokosh_account_id,
            "grantee placement tombstone failed after owner revoke (mirror is authoritative)"
        );
    }

    Ok(StatusCode::NO_CONTENT)
}
