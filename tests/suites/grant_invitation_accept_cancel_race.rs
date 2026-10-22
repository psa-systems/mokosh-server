//! PMS-1486 regression test: an `accept` that loses the race to a
//! concurrent `cancel` must revoke the Bunyip grant it just
//! registered, not just answer the caller with a refusal.
//!
//! The race is reproduced deterministically rather than with real
//! thread timing: the stub Bunyip server's register handler, on
//! receiving `accept`'s `POST /v1/mokosh-grants` call, immediately
//! runs the SAME guarded `UPDATE ... WHERE status = 'pending'` that
//! `cancel` runs, before answering 200. That lands the invitation in
//! `canceled` in the gap between `accept`'s register call and its own
//! guarded local UPDATE, exactly reproducing the failing scenario in
//! the ticket.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::routing::{delete, post};
use axum::{Json, Router};
use chrono::Utc;
use mokosh_test::mokosh_test;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::bunyip_directory::BunyipUserDirectory;
use mokosh_server::modules::auth::grant_invitations::{
    AcceptRefusal, GrantInvitationsService, DEFAULT_TTL,
};

#[derive(Clone)]
struct StubState {
    pool: PgPool,
    revoked_ids: Arc<Mutex<Vec<Uuid>>>,
}

async fn register(State(state): State<StubState>, Json(body): Json<Value>) -> Json<Value> {
    let grant_id: Uuid = body["grant_id"]
        .as_str()
        .expect("grant_id on register body")
        .parse()
        .expect("grant_id is a uuid");

    // Simulate the concurrent `cancel` winning the race the instant
    // the registration lands on Bunyip's side, before `accept`'s own
    // guarded local UPDATE runs.
    sqlx::query(
        "UPDATE mokosh_grant_invitations \
         SET status = 'canceled', canceled_at = NOW(), updated_at = NOW() \
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(grant_id)
    .execute(&state.pool)
    .await
    .expect("simulate the concurrent cancel");

    Json(json!({
        "grant_id": grant_id,
        "granted_at": Utc::now(),
        "revoked_at": Value::Null,
    }))
}

async fn revoke(
    State(state): State<StubState>,
    Path(id): Path<Uuid>,
    Json(_body): Json<Value>,
) -> axum::http::StatusCode {
    state.revoked_ids.lock().expect("lock revoked_ids").push(id);
    axum::http::StatusCode::NO_CONTENT
}

async fn seed_tenant(pool: &PgPool, slug: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, $2, $3, 'active', 'org')",
    )
    .bind(id)
    .bind(format!("Tenant {slug}"))
    .bind(slug)
    .execute(pool)
    .await
    .expect("seed tenant");
    id
}

#[mokosh_test]
async fn accept_losing_the_race_to_cancel_revokes_the_bunyip_grant(pool: PgPool) {
    let revoked_ids = Arc::new(Mutex::new(Vec::new()));
    let stub_state = StubState {
        pool: pool.clone(),
        revoked_ids: revoked_ids.clone(),
    };
    let router = Router::new()
        .route("/v1/mokosh-grants", post(register))
        .route("/v1/mokosh-grants/{id}", delete(revoke))
        .with_state(stub_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub bunyip server");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("stub bunyip serve");
    });

    let directory = BunyipUserDirectory::for_tests(&format!("http://{addr}"));

    let tenant_id = seed_tenant(&pool, "acme-race").await;
    let owner = Uuid::new_v4();
    let grantee = Uuid::new_v4();

    let created = GrantInvitationsService::create(
        &pool,
        tenant_id,
        owner,
        Some(grantee),
        "grantee@example.com",
        "manager",
        DEFAULT_TTL,
    )
    .await
    .expect("create invitation");
    let invitation_id = created.invitation.id;

    let outcome = GrantInvitationsService::accept(
        &pool,
        &created.accept_token,
        grantee,
        owner,
        Some(&directory),
    )
    .await
    .expect("accept call");

    assert!(
        matches!(outcome, Err(AcceptRefusal::Canceled)),
        "accept must report the invitation canceled after losing the race, got {outcome:?}"
    );

    // The real assertion: losing the race must heal the orphan, not
    // merely report the refusal.
    assert_eq!(
        revoked_ids.lock().expect("lock revoked_ids").as_slice(),
        [invitation_id],
        "accept losing the race to cancel must revoke the bunyip grant it registered"
    );

    // No mirror row: the accept never reached the success path.
    let mirror_row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT bunyip_grant_id FROM mokosh_bunyip_grants WHERE bunyip_grant_id = $1",
    )
    .bind(invitation_id)
    .fetch_optional(&pool)
    .await
    .expect("query mirror");
    assert!(
        mirror_row.is_none(),
        "a lost race must not write the mokosh_bunyip_grants mirror"
    );
}
