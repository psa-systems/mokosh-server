//! BUNYIP-674 integration tests for the `mokosh_bunyip_grants` mirror
//! and the `mokosh_grant_changed` webhook receiver.
//!
//! Exercises the DB shape directly (via
//! `MokoshBunyipGrantService::upsert` / `is_grant_active`), which is
//! the same code path the webhook receiver runs against a verified
//! payload. HMAC verification is unit-tested inside `bunyip_webhook.rs`
//! and does not need a full HTTP boot here.

mod common;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::mokosh_bunyip_grants::{
    clear_cache_for_tests, MokoshBunyipGrantService,
};

fn triple() -> (Uuid, Uuid, Uuid, &'static str) {
    (
        Uuid::new_v4(), // bunyip_grant_id
        Uuid::new_v4(), // owner
        Uuid::new_v4(), // grantee
        "acme",         // mokosh_account_id
    )
}

#[sqlx::test]
async fn upsert_granted_then_is_grant_active_returns_true(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("manager"),
        now,
        None,
    )
    .await
    .expect("upsert granted");

    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .expect("is_grant_active")
    );
}

#[sqlx::test]
async fn upsert_revoked_is_seen_as_inactive(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    // First, a granted event.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("admin"),
        now,
        None,
    )
    .await
    .expect("granted");
    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );

    // Then a revoked event. The cache invalidation on write is what
    // makes the very next read see the change without waiting for the
    // 30s TTL.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        now,
        Some(now),
    )
    .await
    .expect("revoked");
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );
}

#[sqlx::test]
async fn is_grant_active_for_an_unknown_triple_is_false(pool: PgPool) {
    clear_cache_for_tests();
    // No upsert - the caller has never had a grant to this account.
    let unknown_grantee = Uuid::new_v4();
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, unknown_grantee, "acme")
            .await
            .unwrap()
    );
}

#[sqlx::test]
async fn a_revoked_row_can_be_reinstated_by_a_later_granted_event(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("manager"),
        now,
        None,
    )
    .await
    .unwrap();
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        now,
        Some(now),
    )
    .await
    .unwrap();
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );

    // A `granted` event AFTER the revoked one is Bunyip saying the
    // grant is live again (a revoke-then-regrant on Bunyip mints a new
    // bunyip_grant_id but keeps the same triple). The mirror follows.
    let new_grant_id = Uuid::new_v4();
    MokoshBunyipGrantService::upsert(
        &pool,
        new_grant_id,
        owner,
        grantee,
        account,
        Some("read_only"),
        now,
        None,
    )
    .await
    .unwrap();
    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );
}

#[sqlx::test]
async fn a_duplicate_granted_event_is_idempotent(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    // First delivery.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("technician"),
        now,
        None,
    )
    .await
    .unwrap();
    // A retried delivery of the same event carries the same body; the
    // upsert-on-triple keeps ONE row.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("technician"),
        now,
        None,
    )
    .await
    .unwrap();

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mokosh_bunyip_grants \
         WHERE grantee_bunyip_user_id = $1 AND mokosh_account_id = $2",
    )
    .bind(grantee)
    .bind(account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1);
    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );
}

/// A `revoked` event for a triple the mirror never saw the `granted`
/// for still lands the row in the revoked state (the receiver's
/// no-op-on-unknown contract). The parent BUNYIP-674 ticket names this
/// as the "race where mokosh missed the granted webhook still lands
/// in the correct state" case.
#[sqlx::test]
async fn a_revoked_event_for_an_unknown_triple_lands_the_revoked_row(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        now,
        Some(now),
    )
    .await
    .expect("revoked on unknown triple");

    let (revoked_at,): (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
        "SELECT revoked_at FROM mokosh_bunyip_grants \
         WHERE grantee_bunyip_user_id = $1 AND mokosh_account_id = $2",
    )
    .bind(grantee)
    .bind(account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(revoked_at.is_some());
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );
}

use mokosh_server::modules::auth::oidc_rs::AtClaims;
use mokosh_server::modules::auth::AuthService;
use mokosh_server::Database;

fn claims_with_grant(sub: Uuid, mokosh_account_id: Option<&str>) -> AtClaims {
    AtClaims {
        iss: "https://bunyip.test".into(),
        sub: sub.to_string(),
        aud: "https://api.mokosh.test".into(),
        client_id: "mokosh".into(),
        scope: "openid".into(),
        exp: 0,
        iat: 0,
        bunyip_role: Some("subscriber".to_string()),
        mokosh_grant_id: mokosh_account_id.map(|_| Uuid::new_v4().to_string()),
        mokosh_grant_role: mokosh_account_id.map(|_| "manager".to_string()),
        mokosh_grant_account_id: mokosh_account_id.map(str::to_string),
    }
}

/// BUNYIP-674 end-to-end: a token without a grant claim passes the gate
/// with no DB touch; a token with an active grant passes; a token whose
/// grant is revoked is refused with Forbidden.
#[sqlx::test]
async fn ensure_grant_still_active_if_claimed_gates_on_the_mirror(pool: PgPool) {
    clear_cache_for_tests();
    let auth = AuthService::new(Database::from_pool(pool.clone()), "test-secret".into());

    let grantee = Uuid::new_v4();
    let account = "acme";

    // No grant claim: always Ok.
    auth.ensure_grant_still_active_if_claimed(&claims_with_grant(grantee, None))
        .await
        .expect("no grant claim => pass");

    // Grant claim but no matching mirror row: Forbidden.
    let err = auth
        .ensure_grant_still_active_if_claimed(&claims_with_grant(grantee, Some(account)))
        .await
        .expect_err("no mirror row => Forbidden");
    assert!(
        matches!(err, mokosh_server::utils::error::AppError::Forbidden(_)),
        "expected Forbidden, got {err:?}"
    );

    // Now seed an active grant on the mirror.
    let now = Utc::now();
    MokoshBunyipGrantService::upsert(
        &pool,
        Uuid::new_v4(), // bunyip_grant_id
        Uuid::new_v4(), // owner
        grantee,
        account,
        Some("manager"),
        now,
        None,
    )
    .await
    .expect("upsert active grant");

    auth.ensure_grant_still_active_if_claimed(&claims_with_grant(grantee, Some(account)))
        .await
        .expect("active grant => pass");

    // Revoke it and the same claim now fails.
    MokoshBunyipGrantService::upsert(
        &pool,
        Uuid::new_v4(),
        Uuid::new_v4(),
        grantee,
        account,
        None,
        now,
        Some(now),
    )
    .await
    .expect("revoke grant");
    let err = auth
        .ensure_grant_still_active_if_claimed(&claims_with_grant(grantee, Some(account)))
        .await
        .expect_err("revoked grant => Forbidden");
    assert!(matches!(
        err,
        mokosh_server::utils::error::AppError::Forbidden(_)
    ));
}
