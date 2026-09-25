//! PMS-1210: the grantee-side "Leave account" endpoint.
//!
//! Cloudflare's account-membership model lets a member leave an account they
//! were granted access to from their own dashboard, distinct from an
//! owner-side revoke. Before this ticket a Mokosh grantee had no such path
//! (only [`bunyip_webhook`]'s owner-side revoke) and had to ask the owner to
//! revoke.
//!
//! The endpoint lives on mokosh-server because every feature must work in
//! both deployment modes (SaaS and standalone); the SPA in mokosh-apps drives
//! it from the `TenantSwitcher`. In SaaS mode the mirror on Bunyip picks up
//! the revoke through the existing webhook shape; the outbound "grantee-left"
//! call to bunyip-api is deferred to a companion BUNYIP ticket (see the
//! PMS-1210 description), because the mokosh-server side is
//! standalone-complete without it and the SaaS half needs a receiver on the
//! other end.
//!
//! [`bunyip_webhook`]: super::bunyip_webhook
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::delete,
    Router,
};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use super::mokosh_bunyip_grants::{GranteeLeaveOutcome, MokoshBunyipGrantService};
use crate::modules::auth::middleware::RequireAuth;
use crate::utils::error::{AppError, AppResult};

/// Wiring state: only the `PgPool`, because the grants table sits outside
/// the standard tenant-scoped surface (cross-tenant BY DESIGN, see
/// `mokosh_bunyip_grants.rs`'s module doc) and its service takes a pool
/// directly.
#[derive(Clone)]
pub struct MyGrantsRouterState {
    pub pool: Arc<PgPool>,
}

/// `/my-grants/*` router. Mounted at the top of `/api/v1` beside `/auth`.
///
/// The mount point is deliberately NOT under `/auth`: a "leave account"
/// gesture is a caller acting on themselves through the identity plane and
/// so nests alongside the other identity routes rather than under the
/// auth-of-record ones.
pub fn my_grants_routes(pool: PgPool) -> Router {
    let state = MyGrantsRouterState {
        pool: Arc::new(pool),
    };
    Router::new()
        .route("/{id}", delete(leave_grant))
        .with_state(state)
}

/// `DELETE /api/v1/my-grants/{id}`.
///
/// - 204 on a fresh revoke.
/// - 204 on a replay against a row that is already revoked (idempotent, so
///   a client that lost track of state does not see two different answers
///   for the same request).
/// - 404 on an id that is not the caller's own grant. Enumeration-resistant
///   by construction: the query names `(id, grantee_bunyip_user_id)` in one
///   predicate, so an id that belongs to somebody else answers the same as
///   an id that does not exist. Matches the owner-side revoke's shape.
async fn leave_grant(
    State(state): State<MyGrantsRouterState>,
    RequireAuth(user): RequireAuth,
    Path(row_id): Path<Uuid>,
) -> AppResult<impl IntoResponse> {
    // Resolve the caller's Bunyip sub from their own `users` row. Migration
    // 226 pinned `(bunyip_user_id, tenant_id)` unique, so the placement rows
    // for one Bunyip identity across many Mokosh tenants all carry the same
    // `bunyip_user_id`; any one placement answers for the sub. Read on the
    // migrator pool because `users` is RLS-covered and this handler holds no
    // tenant GUC (the endpoint is identity-plane, not tenant-scoped).
    let bunyip_user_id: Option<Uuid> = sqlx::query_scalar(
        // SAFETY (PMS-285): identity-plane read of the caller's own row. No
        // tenant GUC because the endpoint is cross-tenant by design: the
        // caller might be revoking a row on a tenant they are not currently
        // scoped to.
        "SELECT bunyip_user_id FROM users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_optional(state.pool.as_ref())
    .await?;

    let Some(bunyip_user_id) = bunyip_user_id else {
        // A caller with no `bunyip_user_id` (a pre-Bunyip local user) has no
        // grant to leave. Answer 404 rather than 400 to match the id-based
        // shape below, so a legacy caller and a foreign id are told the
        // same story.
        return Ok(StatusCode::NOT_FOUND);
    };

    match MokoshBunyipGrantService::grantee_leave(state.pool.as_ref(), row_id, bunyip_user_id)
        .await?
    {
        GranteeLeaveOutcome::Revoked | GranteeLeaveOutcome::AlreadyRevoked => {
            Ok(StatusCode::NO_CONTENT)
        }
        GranteeLeaveOutcome::NotFound => Ok(StatusCode::NOT_FOUND),
    }
}

// Silence unused-import warnings on the smaller feature sets; every symbol
// is used above under the default features.
#[allow(dead_code)]
fn _unused_error(_: AppError) {}
