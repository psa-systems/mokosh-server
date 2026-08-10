//! PMS-729 phase 2 H5: portal password-policy HTTP wire tests.
//!
//! Unit tests in `src/utils/password_policy.rs` cover the policy logic;
//! this suite pins the endpoint behaviour: the setup-password route
//! rejects a weak candidate with 400 + a user-safe message BEFORE
//! writing the hash, and does so only AFTER the token has been verified
//! (so a bad-token replay still surfaces as 410, not "your password is
//! too weak").

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Seed a company + a portal-enabled contact that has NOT redeemed a
/// setup token yet (`portal_password_hash` still NULL). Returns the
/// contact id so tests can mint tokens against it.
async fn seed_contact_awaiting_setup(pool: &PgPool, email: &str) -> Uuid {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email, is_portal_user
        )
        VALUES ($1, $2, $3, 'Portal', 'Contact', $4, TRUE)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed setup-pending contact");
    id
}

/// Mint a fresh setup token for `contact_id` with a known secret and a
/// far-future expiry. Returns the plaintext `{contact_id}.{secret}`
/// form the client would receive in the email.
async fn seed_setup_token(pool: &PgPool, contact_id: Uuid, secret: &str) -> String {
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash setup secret");
    sqlx::query(
        r#"
        INSERT INTO portal_setup_tokens (tenant_id, contact_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .bind(&hash)
    .bind(chrono::Utc::now() + chrono::Duration::hours(72))
    .execute(pool)
    .await
    .expect("seed setup token");
    format!("{contact_id}.{secret}")
}

/// POST /portal/auth/setup-password + return the raw response.
async fn setup(app: &common::TestApp, token: &str, password: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/portal/auth/setup-password"))
        .json(&serde_json::json!({ "token": token, "password": password }))
        .send()
        .await
        .expect("send setup-password")
}

// AC (H5 length floor): a candidate under 12 chars is rejected with a
// 400 + user-safe length message. Nothing hits the DB write.
#[sqlx::test]
async fn rejects_too_short_password(pool: PgPool) {
    let contact = seed_contact_awaiting_setup(&pool, "under12@acme.example").await;
    let token = seed_setup_token(&pool, contact, "setup-secret-abcdefghij").await;
    let app = common::boot(pool.clone()).await;

    let resp = setup(&app, &token, "Short1!").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("400 body");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("at least 12"),
        "unexpected body: {body}"
    );

    // Password hash NOT written.
    let hash: Option<String> =
        sqlx::query_scalar("SELECT portal_password_hash FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&app.pool)
            .await
            .expect("select hash");
    assert!(hash.is_none(), "reject-shall-not-write");
}

// AC (H5 blocklist): a candidate on the embedded blocklist is rejected
// with a 400 + user-safe "well-known" message.
#[sqlx::test]
async fn rejects_common_password_from_blocklist(pool: PgPool) {
    let contact = seed_contact_awaiting_setup(&pool, "common@acme.example").await;
    let token = seed_setup_token(&pool, contact, "setup-secret-abcdefghij2").await;
    let app = common::boot(pool.clone()).await;

    let resp = setup(&app, &token, "password12345").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("400 body");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("well-known") || msg.contains("common"),
        "unexpected body: {body}"
    );
}

// AC (H5 zxcvbn): a candidate the length gate lets through but zxcvbn
// scores as guessable is rejected with a 400 + user-safe message.
#[sqlx::test]
async fn rejects_weak_zxcvbn_score(pool: PgPool) {
    let contact = seed_contact_awaiting_setup(&pool, "weak@acme.example").await;
    let token = seed_setup_token(&pool, contact, "setup-secret-abcdefghij3").await;
    let app = common::boot(pool.clone()).await;

    let resp = setup(&app, &token, "aaaaaaaaaaaaaa").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("400 body");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("too easy") || msg.contains("guess"),
        "unexpected body: {body}"
    );
}

// AC (H5 context hints): a candidate that quotes the user's own email
// is rejected even if it would otherwise pass zxcvbn on entropy alone.
#[sqlx::test]
async fn rejects_password_that_quotes_the_email(pool: PgPool) {
    let contact = seed_contact_awaiting_setup(&pool, "alice.jones@acme.example").await;
    let token = seed_setup_token(&pool, contact, "setup-secret-abcdefghij4").await;
    let app = common::boot(pool.clone()).await;

    // Password IS the email verbatim. Long enough on paper (>= 12
    // chars) but with the email in the zxcvbn context hint list the
    // score drops to 0 (matches a user input literally) so the policy
    // layer rejects with 400.
    let resp = setup(&app, &token, "alice.jones@acme.example").await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "email-as-password should be 400 (context-hint reject)"
    );
}

// AC (H5 ordering): a valid + strong password on a REPLAYED token
// still surfaces as 410 Gone, not "your password is fine but too weak".
// This proves the policy check runs AFTER token verification.
#[sqlx::test]
async fn replay_beats_policy_check(pool: PgPool) {
    let contact = seed_contact_awaiting_setup(&pool, "order@acme.example").await;
    let token = seed_setup_token(&pool, contact, "setup-secret-abcdefghij5").await;
    let app = common::boot(pool.clone()).await;

    // Burn the token with a strong password.
    let strong = "Kq7$mZ2n#PxR9wLf";
    let first = setup(&app, &token, strong).await;
    assert_eq!(
        first.status(),
        reqwest::StatusCode::NO_CONTENT,
        "first use should 2xx"
    );

    // Replay with a weak password. Server sees the token is used
    // BEFORE it checks the password, so response is 410 Gone (the
    // token status is the real problem; password is irrelevant now).
    let replay = setup(&app, &token, "short1").await;
    assert_eq!(
        replay.status(),
        reqwest::StatusCode::GONE,
        "replay wins over policy"
    );
}

// AC (H5 happy path): a strong password passes and the hash is written.
#[sqlx::test]
async fn strong_password_accepted(pool: PgPool) {
    let contact = seed_contact_awaiting_setup(&pool, "strong@acme.example").await;
    let token = seed_setup_token(&pool, contact, "setup-secret-abcdefghij6").await;
    let app = common::boot(pool.clone()).await;

    let strong = "Kq7$mZ2n#PxR9wLf";
    let ok = setup(&app, &token, strong).await;
    assert_eq!(
        ok.status(),
        reqwest::StatusCode::NO_CONTENT,
        "strong password should 2xx, got {}",
        ok.status()
    );
    let hash: Option<String> =
        sqlx::query_scalar("SELECT portal_password_hash FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&app.pool)
            .await
            .expect("select hash");
    assert!(hash.is_some(), "hash written on happy path");
}
