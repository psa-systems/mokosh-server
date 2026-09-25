//! PMS-1244: `reset_password` must run Argon2 `verify_password` exactly
//! once per redemption attempt, by looking the row up via its
//! equality-matchable `lookup_hash` instead of scanning every non-expired
//! candidate row for the user and verifying each in turn.
//!
//! Kept to one test in its own binary on purpose (the `attachment_download_
//! streaming.rs` shape): `verify_password_call_count()` is a process-wide
//! counter, and `cargo test` runs several cases per binary concurrently, so
//! a sibling case's own password verifies (login, another reset, ...) would
//! land on this counter and make the assertion flaky or wrong.

mod common;

use chrono::{Duration, Utc};
use mokosh_server::utils::crypto::{hash_password, sha256_hex, verify_password_call_count};
use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

/// Insert a redeemable `password_reset_tokens` row for `user_id` with a
/// known secret, both hashes PMS-1244 needs.
async fn seed_candidate(pool: &PgPool, tenant_id: Uuid, user_id: Uuid, secret: &str) {
    let token_hash = hash_password(secret).await.expect("hash secret");
    let lookup_hash = sha256_hex(secret);
    sqlx::query(
        "INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, lookup_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(&lookup_hash)
    .bind(Utc::now() + Duration::hours(1))
    .execute(pool)
    .await
    .expect("insert candidate reset token");
}

#[mokosh_test]
async fn reset_password_verifies_exactly_once_with_multiple_candidates(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;

    // Five other live candidate rows for the same user - the shape the old
    // O(N) scan-and-verify loop paid for on every redemption attempt.
    for i in 0..5 {
        seed_candidate(
            &app.pool,
            common::DEFAULT_TENANT_ID,
            admin_id,
            &format!("decoy-secret-{i}"),
        )
        .await;
    }
    let real_secret = "the-real-secret-value-abcdef";
    seed_candidate(&app.pool, common::DEFAULT_TENANT_ID, admin_id, real_secret).await;

    // Success case: the correct token redeems and costs exactly one verify.
    let before = verify_password_call_count();
    let new_password = "brand-new-password-123";
    let resp = app
        .client
        .post(app.url("/api/v1/auth/reset-password"))
        .json(&serde_json::json!({
            "token": format!("{admin_id}.{real_secret}"),
            "new_password": new_password,
            "confirm_password": new_password,
        }))
        .send()
        .await
        .expect("send reset-password");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a valid reset must succeed"
    );
    assert_eq!(
        verify_password_call_count() - before,
        1,
        "a successful redemption with multiple candidate rows must run exactly one Argon2 verify"
    );

    // Failure case: seed a fresh candidate set (the one above is now used)
    // and submit a token whose lookup hash matches nothing. Still exactly
    // one verify (against the PMS-1244 dummy hash), not zero and not N.
    for i in 0..5 {
        seed_candidate(
            &app.pool,
            common::DEFAULT_TENANT_ID,
            admin_id,
            &format!("second-round-decoy-{i}"),
        )
        .await;
    }
    let before = verify_password_call_count();
    let resp = app
        .client
        .post(app.url("/api/v1/auth/reset-password"))
        .json(&serde_json::json!({
            "token": format!("{admin_id}.no-such-secret-matches-any-row"),
            "new_password": new_password,
            "confirm_password": new_password,
        }))
        .send()
        .await
        .expect("send reset-password with unmatched token");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a token matching no row must be rejected"
    );
    assert_eq!(
        verify_password_call_count() - before,
        1,
        "a failed redemption with multiple candidate rows must still run exactly one Argon2 verify, \
         not one per candidate row"
    );
}
