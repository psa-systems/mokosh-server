//! MAPPS-875: SaaS-mode integration tests for the owner outbox.
//!
//! The standalone-mode paths are covered by `owner_grant_management.rs`
//! at the DB level; those paths own state on this side. The SaaS-mode
//! paths call bunyip over HTTP, so exercising them means standing up
//! a stub bunyip that answers the two endpoints
//! (`GET /v1/mokosh-grants`, `DELETE /v1/mokosh-grants/{id}`) with
//! the shapes MAPPS-875 bunyip actually returns. This file boots
//! that stub on a per-test TCP socket, points a
//! `BunyipUserDirectory::for_tests(...)` at it, and asserts:
//!
//! - `list_owner_grants` decodes the envelope response and returns
//!   the grantee identity fields the handler now forwards to the SPA.
//! - `revoke_grant` fires DELETE with the owner in the body, gets a
//!   204, and reports success. An unknown grant (foreign owner or
//!   revoked) surfaces as `Err(AppError::Internal)` since the stub
//!   returns 404 and the client's non-2xx path treats that as a
//!   transport error - matches the production shape where a 404 on
//!   revoke could equally mean "already gone" or "wrong owner" and
//!   the caller can't distinguish without racy re-reads.

mod common;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use serde_json::json;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use uuid::Uuid;

use mokosh_server::modules::auth::bunyip_directory::BunyipUserDirectory;

/// State the stub keeps between requests: a canned list of grants
/// keyed by `owner_bunyip_user_id`, plus a set of ids the caller
/// asked to revoke. Wrapped in `Arc<Mutex>` because the axum handler
/// state is `Clone` and shared across handler calls.
#[derive(Clone, Default)]
struct StubState {
    grants_by_owner: Arc<Mutex<Vec<(Uuid, serde_json::Value)>>>,
    revoked_ids: Arc<Mutex<Vec<Uuid>>>,
}

#[derive(serde::Deserialize)]
struct ListQuery {
    owner_bunyip_user_id: Uuid,
}

async fn list_handler(
    State(state): State<StubState>,
    axum::extract::Query(q): axum::extract::Query<ListQuery>,
) -> Json<serde_json::Value> {
    let rows = state.grants_by_owner.lock().unwrap();
    let matched: Vec<&serde_json::Value> = rows
        .iter()
        .filter_map(|(owner, row)| {
            if *owner == q.owner_bunyip_user_id {
                Some(row)
            } else {
                None
            }
        })
        .collect();
    Json(json!({
        "success": true,
        "data": matched,
        "meta": { "request_id": "test-request-id" },
    }))
}

#[derive(serde::Deserialize)]
struct RevokeBody {
    #[serde(rename = "owner_bunyip_user_id")]
    _owner: Uuid,
}

async fn revoke_handler(
    State(state): State<StubState>,
    Path(id): Path<Uuid>,
    Json(_body): Json<RevokeBody>,
) -> StatusCode {
    let rows = state.grants_by_owner.lock().unwrap();
    // Refuse an unknown id with 404 so the client's error path is
    // reachable; a real bunyip does the same via the pre-read.
    if !rows
        .iter()
        .any(|(_, row)| row["grant_id"].as_str() == Some(&id.to_string()))
    {
        return StatusCode::NOT_FOUND;
    }
    drop(rows);
    state.revoked_ids.lock().unwrap().push(id);
    StatusCode::NO_CONTENT
}

async fn spawn_stub(state: StubState) -> String {
    let app = Router::new()
        .route("/v1/mokosh-grants", get(list_handler))
        .route("/v1/mokosh-grants/{id}", delete(revoke_handler))
        .with_state(state);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind stub bunyip");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve stub bunyip");
    });
    format!("http://{addr}")
}

#[sqlx::test]
async fn list_owner_grants_decodes_the_saas_envelope(_pool: PgPool) {
    let owner = Uuid::new_v4();
    let grantee = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    let state = StubState::default();
    state.grants_by_owner.lock().unwrap().push((
        owner,
        json!({
            "grant_id": grant_id.to_string(),
            "grantee_bunyip_user_id": grantee.to_string(),
            "mokosh_account_id": "acme",
            "role": "technician",
            "granted_at": "2026-01-01T00:00:00Z",
            "grantee_email": "grantee@example.com",
            "grantee_name": "Grantee Person",
        }),
    ));

    let base_url = spawn_stub(state).await;
    let directory = BunyipUserDirectory::for_tests(base_url);

    let grants = directory.list_owner_grants(owner).await.expect("list ok");
    assert_eq!(grants.len(), 1);
    let g = &grants[0];
    assert_eq!(g.grant_id, grant_id);
    assert_eq!(g.grantee_bunyip_user_id, grantee);
    assert_eq!(g.mokosh_account_id, "acme");
    assert_eq!(g.role, "technician");
    assert_eq!(g.grantee_email.as_deref(), Some("grantee@example.com"));
    assert_eq!(g.grantee_name.as_deref(), Some("Grantee Person"));
}

#[sqlx::test]
async fn list_owner_grants_is_empty_for_an_owner_with_none(_pool: PgPool) {
    let owner_present = Uuid::new_v4();
    let owner_empty = Uuid::new_v4();

    let state = StubState::default();
    state.grants_by_owner.lock().unwrap().push((
        owner_present,
        json!({
            "grant_id": Uuid::new_v4().to_string(),
            "grantee_bunyip_user_id": Uuid::new_v4().to_string(),
            "mokosh_account_id": "someone_elses_tenant",
            "role": "read_only",
            "granted_at": "2026-01-01T00:00:00Z",
        }),
    ));

    let base_url = spawn_stub(state).await;
    let directory = BunyipUserDirectory::for_tests(base_url);

    // An owner with no grants returns an empty list, not an error.
    // Distinguishing "no grants" from "bunyip is down" is what makes
    // the outbox page trustworthy - a false empty on an outage would
    // let the owner think they've revoked access they still have.
    let grants = directory
        .list_owner_grants(owner_empty)
        .await
        .expect("list ok");
    assert!(grants.is_empty());
}

#[sqlx::test]
async fn revoke_grant_returns_ok_on_204(_pool: PgPool) {
    let owner = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    let state = StubState::default();
    state.grants_by_owner.lock().unwrap().push((
        owner,
        json!({
            "grant_id": grant_id.to_string(),
            "grantee_bunyip_user_id": Uuid::new_v4().to_string(),
            "mokosh_account_id": "acme",
            "role": "manager",
            "granted_at": "2026-01-01T00:00:00Z",
        }),
    ));
    let revoked_ids = state.revoked_ids.clone();

    let base_url = spawn_stub(state).await;
    let directory = BunyipUserDirectory::for_tests(base_url);

    directory
        .revoke_grant(grant_id, owner)
        .await
        .expect("revoke ok");

    // The stub records the revoked id so the test can pin that the
    // real HTTP call reached the sibling endpoint and carried the
    // right id in the URL.
    let revoked = revoked_ids.lock().unwrap().clone();
    assert_eq!(revoked, vec![grant_id]);
}

#[sqlx::test]
async fn revoke_grant_surfaces_the_404_on_a_foreign_id(_pool: PgPool) {
    let owner = Uuid::new_v4();
    let unknown = Uuid::new_v4();

    let state = StubState::default();
    // Deliberately empty; the id the caller sends is not known to
    // the stub.

    let base_url = spawn_stub(state).await;
    let directory = BunyipUserDirectory::for_tests(base_url);

    // Client treats non-2xx as an internal error (a transport-level
    // failure that must not be silenced as "already revoked");
    // callers upstream decide whether to reveal that to the SPA.
    let result = directory.revoke_grant(unknown, owner).await;
    assert!(result.is_err(), "unknown id must not report success");
}
