//! PMS-729 phase 2 §5 H3: contact forgot-password + reset-password HTTP
//! wire tests, on the contact plane since PMS-1025 (ported in PMS-1031).
//!
//! `POST /contact/auth/forgot-password` mints a `portal_setup_tokens` row
//! for a matching contact (PMS-820: the reset reuses the setup-link
//! contract, `{contact_id}.{secret}` hashed with Argon2, single use), and
//! `POST /contact/auth/reset-password` redeems it: 204, then 410 on a
//! replay, 400 on an expired or unknown token, 400 with the policy
//! message on a weak password with the token left unused.
//!
//! Two groups the retired portal pinned are gone with it. Its
//! `PUT /portal/auth/me/password` change-password route has no contact
//! plane counterpart (`PUT /contact/auth/me` edits the profile and
//! carries no password field). And a successful reset revoked every live
//! refresh token; `ContactAuthService::setup_password` writes the hash
//! and marks the token used without touching `contact_sessions`. Both
//! are recorded on the PMS-1031 follow-up as coverage the cut removed.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const STRONG: &str = "Xy9#pQ4v!Lm2wRt7";

async fn seed_portal_contact(pool: &PgPool, email: &str) -> common::PortalContact {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    common::seed_portal_contact(pool, company, email, &[]).await
}

async fn forgot(app: &common::TestApp, slug: &str, email: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/contact/auth/forgot-password"))
        .json(&serde_json::json!({ "slug": slug, "email": email }))
        .send()
        .await
        .expect("send forgot-password")
}

async fn reset(app: &common::TestApp, token: &str, password: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/contact/auth/reset-password"))
        .json(&serde_json::json!({ "token": token, "password": password }))
        .send()
        .await
        .expect("send reset-password")
}

/// Insert a reset-token row directly with a known secret so the test can
/// present the plaintext. Bypasses `forgot()` because the plaintext only
/// ever leaves the service inside the reset mail. Returns the row id and
/// the token the customer would paste.
async fn seed_reset_token(
    pool: &PgPool,
    contact_id: Uuid,
    secret: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> (Uuid, String) {
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash");
    let token_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO portal_setup_tokens (id, tenant_id, contact_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(token_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .bind(&hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("insert reset token");
    (token_id, format!("{contact_id}.{secret}"))
}

fn in_thirty_minutes() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::minutes(30)
}

// AC (H3 forgot): unknown email still returns 204. Enumeration-resistant.
#[sqlx::test]
async fn forgot_password_unknown_email_still_204(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let resp = forgot(&app, &contact.slug, "does-not-exist@example.com").await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    let resp = forgot(&app, "no-such-company", &contact.email).await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
}

// AC (H3 forgot): known email returns 204 AND inserts a row.
#[sqlx::test]
async fn forgot_password_known_email_204_and_writes_row(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM portal_setup_tokens WHERE contact_id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .expect("count before");
    assert_eq!(before, 0);

    let resp = forgot(&app, &contact.slug, &contact.email).await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM portal_setup_tokens WHERE contact_id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .expect("count after");
    assert_eq!(after, 1, "reset token row should exist");
}

// AC (H3 reset): a valid + unused + unexpired token with a strong
// password sets the hash and returns 204.
#[sqlx::test]
async fn reset_password_happy_path(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;
    let (token_id, token) =
        seed_reset_token(&pool, contact.id, "reset-secret-abcdefghij", in_thirty_minutes()).await;

    let resp = reset(&app, &token, STRONG).await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Hash rotated: the new password verifies, and signs in.
    let new_hash: Option<String> =
        sqlx::query_scalar("SELECT portal_password_hash FROM contacts WHERE id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .expect("select hash");
    let new_hash = new_hash.expect("hash written after reset");
    assert!(
        mokosh_server::utils::crypto::verify_password(STRONG, &new_hash).expect("verify"),
        "new password verifies"
    );
    let login = common::contact_login_response(&app, &contact, STRONG).await;
    assert_eq!(login.status(), reqwest::StatusCode::OK, "new password signs in");
    let old = common::contact_login_response(&app, &contact, common::CONTACT_PASSWORD).await;
    assert_eq!(
        old.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "old password is refused"
    );

    // Token marked used.
    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM portal_setup_tokens WHERE id = $1")
            .bind(token_id)
            .fetch_one(&pool)
            .await
            .expect("select used_at");
    assert!(used_at.is_some(), "token marked used");
}

// AC (H3 reset): a replayed token returns 410 Gone. A weak password in
// the replay body does NOT change that: the token check wins.
#[sqlx::test]
async fn reset_password_replay_returns_410_regardless_of_password(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;
    let (_, token) =
        seed_reset_token(&pool, contact.id, "reset-secret-abcdefghij2", in_thirty_minutes()).await;

    let first = reset(&app, &token, STRONG).await;
    assert_eq!(first.status(), reqwest::StatusCode::NO_CONTENT);

    // Replay with a weak password. Token status wins over policy.
    let replay = reset(&app, &token, "short").await;
    assert_eq!(replay.status(), reqwest::StatusCode::GONE);
}

// AC (H3 reset): an expired token is 400, distinct from replay.
#[sqlx::test]
async fn reset_password_expired_returns_400(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;
    let (_, token) = seed_reset_token(
        &pool,
        contact.id,
        "reset-secret-abcdefghij3",
        chrono::Utc::now() - chrono::Duration::hours(1),
    )
    .await;

    let resp = reset(&app, &token, STRONG).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// AC (H3 reset): an unknown or malformed token is 400.
#[sqlx::test]
async fn reset_password_unknown_token_returns_400(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;

    // Unknown contact id + random secret.
    let unknown = format!("{}.random-secret", Uuid::new_v4());
    assert_eq!(
        reset(&app, &unknown, STRONG).await.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    // A real contact id with a secret that verifies against nothing.
    let wrong = format!("{}.random-secret", contact.id);
    assert_eq!(
        reset(&app, &wrong, STRONG).await.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    // Malformed (no dot).
    assert_eq!(
        reset(&app, "no-dot", STRONG).await.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
}

// AC (H3 reset + H5): a valid token + a weak password is 400 with the
// policy message. The token stays unused so the customer can retry.
#[sqlx::test]
async fn reset_password_weak_password_returns_400_and_token_unused(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;
    let (token_id, token) =
        seed_reset_token(&pool, contact.id, "reset-secret-abcdefghij4", in_thirty_minutes()).await;

    let resp = reset(&app, &token, "short").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("400 body");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("at least 12") || msg.contains("well-known") || msg.contains("too easy"),
        "unexpected body: {body}"
    );

    // Token stays unused so the user can try again with a stronger one.
    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM portal_setup_tokens WHERE id = $1")
            .bind(token_id)
            .fetch_one(&pool)
            .await
            .expect("select used_at");
    assert!(used_at.is_none(), "token stays unused after policy reject");

    // And the same token then redeems.
    let retry = reset(&app, &token, STRONG).await;
    assert_eq!(retry.status(), reqwest::StatusCode::NO_CONTENT);
}
