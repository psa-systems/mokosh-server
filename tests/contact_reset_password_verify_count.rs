//! PMS-1244: `set_password_with_token` (the shared body of the contact
//! plane's `setup_password`/`reset_password`) must run Argon2
//! `verify_password` exactly once per redemption attempt, by looking the
//! row up via its equality-matchable `lookup_hash` instead of scanning
//! every non-expired candidate `portal_setup_tokens` row for the contact
//! and verifying each in turn.
//!
//! Kept to one test in its own binary on purpose (the `attachment_download_
//! streaming.rs` shape): `verify_password_call_count()` is a process-wide
//! counter, and `cargo test` runs several cases per binary concurrently, so
//! a sibling case's own password verifies would land on this counter and
//! make the assertion flaky or wrong.

mod common;

use chrono::{Duration, Utc};
use mokosh_server::utils::crypto::{hash_password, sha256_hex, verify_password_call_count};
use sqlx::PgPool;
use uuid::Uuid;

/// Insert a redeemable `portal_setup_tokens` row for `contact_id` with a
/// known secret.
async fn seed_candidate(pool: &PgPool, tenant_id: Uuid, contact_id: Uuid, secret: &str) {
    let token_hash = hash_password(secret).expect("hash secret");
    let lookup_hash = sha256_hex(secret);
    sqlx::query(
        "INSERT INTO portal_setup_tokens (id, tenant_id, contact_id, token_hash, lookup_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(contact_id)
    .bind(&token_hash)
    .bind(&lookup_hash)
    .bind(Utc::now() + Duration::hours(1))
    .execute(pool)
    .await
    .expect("insert candidate setup token");
}

#[sqlx::test]
async fn reset_password_verifies_exactly_once_with_multiple_candidates(pool: PgPool) {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("seed company");
    let contact = common::seed_portal_contact(&pool, company, "user@example.com", &[]).await;
    let app = common::boot(pool.clone()).await;

    // Five other live candidate rows for the same contact - the shape the
    // old O(N) scan-and-verify loop paid for on every redemption attempt.
    for i in 0..5 {
        seed_candidate(
            &app.pool,
            common::DEFAULT_TENANT_ID,
            contact.id,
            &format!("decoy-secret-{i}"),
        )
        .await;
    }
    let real_secret = "the-real-secret-value-abcdef";
    seed_candidate(
        &app.pool,
        common::DEFAULT_TENANT_ID,
        contact.id,
        real_secret,
    )
    .await;

    // Success case: the correct token redeems and costs exactly one verify.
    let before = verify_password_call_count();
    let new_password = "Xy9#pQ4v!Lm2wRt7";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/reset-password"))
        .json(&serde_json::json!({
            "token": format!("{}.{real_secret}", contact.id),
            "password": new_password,
        }))
        .send()
        .await
        .expect("send reset-password");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
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
            contact.id,
            &format!("second-round-decoy-{i}"),
        )
        .await;
    }
    let before = verify_password_call_count();
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/reset-password"))
        .json(&serde_json::json!({
            "token": format!("{}.no-such-secret-matches-any-row", contact.id),
            "password": new_password,
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
