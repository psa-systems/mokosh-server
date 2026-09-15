//! PMS-1210: grantee-side leave-account endpoint.
//!
//! Cloudflare's account-membership model lets a member remove
//! themselves from an account; this module adds the mokosh
//! equivalent. One route today, `DELETE /api/v1/my-grants/{id}`,
//! where `{id}` is the `mokosh_bunyip_grants.id` for a row where
//! the caller is the grantee. Owner-initiated revoke stays on the
//! BUNYIP-673 `POST /v1/grants/{id}/revoke` path (bunyip-api) with
//! its webhook, so the two revoke initiators are distinct HTTP
//! paths and produce distinct audit lines - `revoked_by = 'owner'`
//! vs `'grantee'` on the mirror row (see migration 222).
//!
//! The endpoint is enumeration-resistant: an id owned by a
//! DIFFERENT grantee returns the same 404 as an unknown id, so a
//! caller cannot walk it. An id the caller HAS but has already
//! revoked returns 204 (idempotent), matching the shape the
//! owner-side revoke uses on a re-fired webhook.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::delete,
    Router,
};
use uuid::Uuid;

use super::middleware::RequireAuth;
use super::mokosh_bunyip_grants::MokoshBunyipGrantService;
use crate::db::Database;
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct MyGrantsState {
    pub db: Arc<Database>,
}

/// Mount under `/api/v1/my-grants` in `create_api_router`.
pub fn my_grants_routes(db: Arc<Database>) -> Router {
    let state = MyGrantsState { db };
    Router::new()
        .route("/{id}", delete(leave_grant))
        .with_state(state)
}

async fn leave_grant(
    State(state): State<MyGrantsState>,
    RequireAuth(caller): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    // Load the grant row first so we can (a) verify the caller is
    // the grantee (enumeration-resistant 404 otherwise), and (b)
    // pass the (grantee, mokosh_account_id) pair to
    // `revoke_by_grantee`, which is the atomic UPDATE.
    let row: Option<(Uuid, String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT grantee_bunyip_user_id, mokosh_account_id, revoked_at \
         FROM mokosh_bunyip_grants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(state.db.migrator_pool())
    .await?;

    let (grantee_id, mokosh_account_id, revoked_at) = match row {
        Some(triple) => triple,
        // Unknown id -> 404. Foreign-grantee id -> 404 below. Same
        // wire shape either way, so the caller cannot distinguish.
        None => return Ok(StatusCode::NOT_FOUND),
    };

    if grantee_id != caller.id {
        return Ok(StatusCode::NOT_FOUND);
    }

    if revoked_at.is_some() {
        // Idempotent replay: the caller already left. 204 rather
        // than 404 so a browser that retried across a tab reload
        // does not surface a scary "already gone" error to the
        // user.
        return Ok(StatusCode::NO_CONTENT);
    }

    // Atomic revoke + `revoked_by = 'grantee'` stamp in the same
    // UPDATE. Cache is invalidated inside the service so the very
    // next request from anyone in this process sees the revoke.
    let _updated =
        MokoshBunyipGrantService::revoke_by_grantee(state.db.pool(), caller.id, &mokosh_account_id)
            .await?;

    // Belt-and-braces tombstone on the placement row, mirroring
    // the receiver's `revoked` branch. A failure here is a warn:
    // the mirror is authoritative for the request-time gate, so a
    // dead tombstone leaves the row invisible to any request the
    // caller might make anyway.
    if let Err(e) = sqlx::query(
        "UPDATE users SET deleted_at = COALESCE(deleted_at, NOW()), updated_at = NOW() \
         WHERE bunyip_user_id = $1 \
           AND tenant_id = (SELECT id FROM tenants WHERE slug = $2)",
    )
    .bind(caller.id)
    .bind(&mokosh_account_id)
    .execute(state.db.migrator_pool())
    .await
    {
        tracing::warn!(
            error = %e,
            grantee = %caller.id,
            mokosh_account_id = %mokosh_account_id,
            "grantee placement tombstone failed after leave (mirror is authoritative; request-time gate still refuses)"
        );
    }

    Ok(StatusCode::NO_CONTENT)
}
