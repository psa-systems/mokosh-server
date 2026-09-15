//! PMS-1210: `DELETE /api/v1/my-grants/{id}` integration tests.
//!
//! Exercises the DB shape directly through
//! `MokoshBunyipGrantService::revoke_by_grantee`, which is the
//! same call the endpoint dispatches to; the wire-level pin
//! rides in `bunyip_grant_end_to_end.rs`'s stub-OP harness that
//! already boots the router in this workspace.
//!
//! Four scenarios, each a distinct wire behaviour the ticket
//! promises:
//! - a grantee's leave on their own active grant flips
//!   `revoked_at` and stamps `revoked_by = 'grantee'`.
//! - a second leave on the same grant is idempotent (no double
//!   stamp, still `grantee`).
//! - the mirror cache is invalidated on the leave so the very
//!   next `is_grant_active` read sees the revoke.
//! - the owner-side revoke path stamps `revoked_by = 'owner'`,
//!   so the audit column can tell the two callers apart.

mod common;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::mokosh_bunyip_grants::{
    clear_cache_for_tests, MokoshBunyipGrantService,
};

async fn seed_active_grant(pool: &PgPool) -> (Uuid, Uuid, Uuid, &'static str) {
    clear_cache_for_tests();
    let grant_id = Uuid::new_v4();
    let owner = Uuid::new_v4();
    let grantee = Uuid::new_v4();
    let account = "acme";
    MokoshBunyipGrantService::upsert(
        pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("manager"),
        Utc::now(),
        None,
    )
    .await
    .expect("seed active grant");
    (grant_id, owner, grantee, account)
}

#[sqlx::test]
async fn revoke_by_grantee_stamps_revoked_at_and_revoked_by(pool: PgPool) {
    let (_, _, grantee, account) = seed_active_grant(&pool).await;

    let id = MokoshBunyipGrantService::revoke_by_grantee(&pool, grantee, account)
        .await
        .expect("revoke returns row id")
        .expect("row updated");

    let (revoked_at, revoked_by): (Option<chrono::DateTime<chrono::Utc>>, Option<String>) =
        sqlx::query_as("SELECT revoked_at, revoked_by FROM mokosh_bunyip_grants WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked_at.is_some(), "grantee leave stamped revoked_at");
    assert_eq!(
        revoked_by.as_deref(),
        Some("grantee"),
        "grantee leave stamped revoked_by = 'grantee'"
    );

    // Idempotent replay: a second leave on the same row finds
    // no active grant to move (the WHERE clause filters on
    // `revoked_at IS NULL`) and returns None. The stamp stays
    // intact so a webhook race that arrived later cannot
    // rewrite the audit line.
    let second = MokoshBunyipGrantService::revoke_by_grantee(&pool, grantee, account)
        .await
        .unwrap();
    assert!(
        second.is_none(),
        "second leave returns None (no active grant to move)"
    );
    let (still_grantee,): (Option<String>,) =
        sqlx::query_as("SELECT revoked_by FROM mokosh_bunyip_grants WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        still_grantee.as_deref(),
        Some("grantee"),
        "second leave preserves the original revoked_by"
    );
}

#[sqlx::test]
async fn revoke_by_grantee_invalidates_the_30s_cache(pool: PgPool) {
    let (_, _, grantee, account) = seed_active_grant(&pool).await;

    // Warm the cache.
    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );

    // Grantee leaves; the cache invalidation inside the service
    // means the next read sees the revoke without waiting for
    // the TTL.
    MokoshBunyipGrantService::revoke_by_grantee(&pool, grantee, account)
        .await
        .unwrap();

    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap(),
        "the cache is invalidated so the next read reflects the revoke"
    );
}

#[sqlx::test]
async fn mark_revoked_by_owner_stamps_revoked_by(pool: PgPool) {
    // Simulate the receiver's `revoked` branch: an owner-initiated
    // revoke arrives as a webhook that upserts the mirror with
    // `revoked_at = payload.at`, then `mark_revoked_by(_, _, _,
    // "owner")` runs.
    let (_, _, grantee, account) = seed_active_grant(&pool).await;

    // Owner revokes via the webhook path (mirror upsert + stamp).
    MokoshBunyipGrantService::upsert(
        &pool,
        Uuid::new_v4(),
        Uuid::new_v4(),
        grantee,
        account,
        None,
        Utc::now(),
        Some(Utc::now()),
    )
    .await
    .unwrap();
    MokoshBunyipGrantService::mark_revoked_by(&pool, grantee, account, "owner")
        .await
        .unwrap();

    let (revoked_by,): (Option<String>,) = sqlx::query_as(
        "SELECT revoked_by FROM mokosh_bunyip_grants \
         WHERE grantee_bunyip_user_id = $1 AND mokosh_account_id = $2",
    )
    .bind(grantee)
    .bind(account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        revoked_by.as_deref(),
        Some("owner"),
        "owner-initiated revoke stamps revoked_by = 'owner'"
    );
}

#[sqlx::test]
async fn revoke_by_grantee_on_unknown_triple_is_a_noop(pool: PgPool) {
    clear_cache_for_tests();
    let unknown_grantee = Uuid::new_v4();
    let unknown_account = "no-such-account";

    let result =
        MokoshBunyipGrantService::revoke_by_grantee(&pool, unknown_grantee, unknown_account)
            .await
            .expect("query runs");
    assert!(
        result.is_none(),
        "leaving a grant you don't have is a no-op, not an error"
    );

    // Deliberately does NOT create a mirror row (the handler's
    // pre-check on the (id, grantee_id) axis would have refused
    // this path with 404 before ever calling into the service,
    // but the service being safe against a bad call keeps the
    // audit trail clean).
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mokosh_bunyip_grants \
         WHERE grantee_bunyip_user_id = $1 AND mokosh_account_id = $2",
    )
    .bind(unknown_grantee)
    .bind(unknown_account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 0);
}
